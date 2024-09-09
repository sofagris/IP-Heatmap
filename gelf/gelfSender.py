from pygelf import GelfTcpHandler, GelfUdpHandler, GelfTlsHandler, GelfHttpHandler
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.addHandler(GelfTcpHandler(host='127.0.0.1', port=9401))
# logger.addHandler(GelfUdpHandler(host='127.0.0.1', port=9402))
# logger.addHandler(GelfTlsHandler(host='127.0.0.1', port=9403))
# logger.addHandler(GelfHttpHandler(host='127.0.0.1', port=9404))

logger.info('Testing GELF logging')
