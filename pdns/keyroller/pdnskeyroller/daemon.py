import yaml
import datetime
import logging

from pdnsapi.api import PDNSApi
from pdnskeyroller import domainstate
import pdnskeyroller.keyrollerdomain
from pdnskeyroller.prepublishkeyroll import PrePublishKeyRoll

logger = logging.getLogger(__name__)


class Daemon:
    def __init__(self, configfile):
        self._configfile = configfile
        self._config = self._load_config()

        # Initialize all domains
        self._domains = {}
        api = PDNSApi(**self._config['API'])
        for zone in api.get_zones():
            try:
                zoneconf = pdnskeyroller.keyrollerdomain.KeyrollerDomain(zone.id, api)
                self._domains[zone.id] = zoneconf
            except FileNotFoundError:
                logger.debug(f"No config found for zone {zone.id}")
                continue
            except Exception as e:
                logger.error(f"Unable to load informations for zone {zone.id}")
                continue

    def _load_config(self):
        # These are all the Defaults
        tmp_conf = {
            'keyroller': {
                'loglevel': 'info',
            },
            'API': {
                'version': 1,
                'baseurl': 'http://localhost:8081',
                'server': 'localhost',
                'apikey': '',
                'timeout': '2',
            },
        }

        logger.debug(f"Loading configuration from {self._configfile}")
        try:
            with open(self._configfile, 'r') as f:
                if a := yaml.safe_load(f):
                    for k, v in tmp_conf.items():
                        if isinstance(v, dict) and isinstance(a.get(k), dict):
                            tmp_conf[k].update(a.get(k))
                        if isinstance(v, list) and isinstance(a.get(k), list):
                            tmp_conf[k] = a.get(k)

            loglevel = getattr(logging, tmp_conf['keyroller']['loglevel'].upper())
            if not isinstance(loglevel, int):
                loglevel = logging.INFO
            logger.info(f"Setting loglevel to {loglevel}")
            logging.basicConfig(level=loglevel)

        except FileNotFoundError as e:
            logger.error(f'Unable to load configuration file: {e}')

        return tmp_conf

    def _get_actionable_domains(self):
        now = datetime.datetime.now()
        return [zone for zone, domainconf in self._domains.items() if
                domainconf.next_action_datetime and domainconf.next_action_datetime <= now]

    def update_config(self):
        """
        Should be called when we want to update the config of a running instance (not implemented)

        :return:
        """
        pass

    def run(self):
        actionable_domains = self._get_actionable_domains()
        now = datetime.datetime.now()
        logger.debug(
            f"Found {len(self._domains)} domain(s) ({len(actionable_domains)} actionable)"
        )


        if len(actionable_domains) > 0:
            for domain in actionable_domains:
                keyrollerdomain = self._domains[domain]
                if keyrollerdomain.state.is_rolling:
                    try:
                        logger.info(
                            f"Moving to step {keyrollerdomain.current_step_name} for {keyrollerdomain.zone} roll"
                        )
                        keyrollerdomain.step()
                    except Exception as e:
                        logger.error(f"Unable to advance keyroll: {e}")
                else:
                    next_ksk_roll = keyrollerdomain.next_ksk_roll()
                    next_zsk_roll = keyrollerdomain.next_zsk_roll()
                    if next_zsk_roll is not None and next_zsk_roll <= now:
                        try:
                            logger.info(
                                f"Starting pre-publish ZSK keyroll for {keyrollerdomain.zone} ({keyrollerdomain.config.zsk_algo} algo)"
                            )
                            roll = PrePublishKeyRoll()
                            roll.initiate(keyrollerdomain.zone, keyrollerdomain.api, 'zsk', keyrollerdomain.config.zsk_algo)
                            keyrollerdomain.state.current_roll = roll
                            domainstate.to_api(keyrollerdomain.zone, keyrollerdomain.api, keyrollerdomain.state)
                        except Exception as e:
                            logger.error(f"Unable to start keyroll: {e}")
                    elif next_ksk_roll is not None and next_ksk_roll <= now:
                        try:
                            logger.info(
                                f"Starting pre-publish KSK keyroll for {keyrollerdomain.zone} ({keyrollerdomain.config.zsk_algo} algo)"
                            )
                            roll = PrePublishKeyRoll()
                            roll.initiate(keyrollerdomain.zone, keyrollerdomain.api, 'ksk', keyrollerdomain.config.ksk_algo)
                            keyrollerdomain.state.current_roll = roll
                            domainstate.to_api(keyrollerdomain.zone, keyrollerdomain.api, keyrollerdomain.state)
                        except Exception as e:
                            logger.error(f"Unable to start keyroll: {e}")
        else:
            logger.info("No action taken")
