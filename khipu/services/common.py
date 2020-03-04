# -*- coding: utf-8 -*-
import hashlib
import hmac
import logging
import requests
import urllib.request
import urllib.parse
import urllib.error

from requests.exceptions import RequestException, Timeout, ConnectionError

from ..exceptions import KhipuError

KHIPU_API_VERSION = '2.0'
logger = logging.getLogger(__name__)


class KhipuService(object):

    def __init__(self, receiver_id, secret, service_name, **kwargs):
        # URL del servicio
        self.api_url = "https://khipu.com/api/{}/".format(KHIPU_API_VERSION)
        # Data que procesara el servicio
        self.data = {}
        # id del cobrador
        self.receiver_id = receiver_id
        # Llave del cobrador
        self.secret = secret
        # Nombre del servicio
        self.service_name = service_name
        # Metodo que se usara
        self.method = None
        # URL donde esta el servicio
        self.path = None
        # Datos de respuesta del Servicio
        self.data_response = {}

    def do_hash(self):
        """
        Genera el Hash que requiere khipu.
        """
        secret_key = self.secret.encode('utf-8')
        concatenation = self.concatenated().encode('utf-8')
        result_hash = hmac.new(
            key=secret_key,
            msg=concatenation,
            digestmod=hashlib.sha256
            ).hexdigest()
        return result_hash

    def concatenated(self):
        """
        El orden de los valores debe ser METODO&URL&LOS_PARAMETROS_A_ENVIAR
        """
        cad = "&".join(['%s=%s' % ((urllib.parse.quote(str(k), safe=''), urllib.parse.quote(str(v), safe=''))) for k, v in self.data.items()])  # noqa
        cad = "&" + cad if cad else ''
        concat = '{}&{}'.format(self.method, urllib.parse.quote(self.get_url_service(), safe='')) + cad  # noqa
        return concat

    def get_url_service(self):
        """
        Generar la URL final de la API a consumir.
        """
        return self.api_url + self.path

    def get_headers(self):
        """
        Es encesario que el hash sea enviado via token.
        """
        return {
            'Authorization': "{}:{}".format(self.receiver_id, self.do_hash())}

    def request(self):
        """
        Regust que consumira el API por un metodo en especifico.
        """
        data_send_key = 'params' if self.method == 'GET' else 'data'
        try:
            r = requests.request(
                method=self.method,
                url=self.get_url_service(),
                headers=self.get_headers(),
                **{data_send_key: self.data}
            )
        except Timeout:
            msg = "Error Timeout. Path: {}. Data: {}.".format(
                self.get_url_service(), self.data)
            raise KhipuError(msg)
        except ConnectionError:
            msg = "Error ConnectionError. Path: {}. Data: {}.".format(
                self.get_url_service(), self.data)
            raise KhipuError(msg)
        except RequestException:
            msg = 'Error RequestException. Path: {}. Data: {}.'.format(
                self.get_url_service(), self.data)
            raise KhipuError(msg)

        if r.status_code in [200, 201]:
            self.data_response = r.json()
        else:
            msg = 'Error {} {} respuesta API'.format(r.status_code, r.json())
            logger.error(msg)
            raise KhipuError(msg)

    def response(self):
        """
        Obtener datos de respuesta del servicio Khipu
        """
        return self.data_response
