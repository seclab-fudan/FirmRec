import os
import json
import base64
import codecs


class PoCInfo:
    """
    Information of Proof-of-concept

    :ivar keywords: keywords used to match entry functions or source input
    :ivar input_info: information of input protocol and payload
    """

    SUPPORTED_PROTOCOLS = ["kv", "raw"]

    def __init__(self, vuln_name, keywords, input_info):
        self.vuln_name = vuln_name
        self.keywords = keywords
        self.input_info = input_info

    @property
    def protocols(self):
        return self.input_info.keys()

    def get_payload(self, protocol):
        """
        Get payload of specific protocol

        :param protocol: input protocol/paradigm
        :return: payload of target protocol
        """
        if protocol == "kv":
            orig_kv = self.input_info.get("kv", {})
            kv = dict()
            for k, v in orig_kv.items():
                k_enc = codecs.encode(k, "utf-8")
                v_enc = codecs.encode(v, "utf-8")
                kv[k_enc] = v_enc
            return kv
        elif protocol == "raw":
            orig_raw = self.input_info.get("raw", [])
            res = []
            for raw in orig_raw:
                enc = codecs.encode(raw, "utf-8")
                enc = base64.b64decode(enc)
                res.append(enc)
            return res

        if protocol not in self.protocols:
            return b""

        payload = self.input_info.get(protocol)
        assert payload and isinstance(payload, str), payload
        payload = codecs.encode(payload, "utf-8")
        return payload

    @classmethod
    def load_from_file(cls, file_path):
        """Load PoCInfo from json file"""
        with open(file_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        vuln_name = os.path.basename(file_path).replace(".json", "")
        return cls.load_from_json(vuln_name, data)
    
    @classmethod
    def load_from_json(cls, vuln_name, data):
        """Load PoCInfo from json data"""
        keywords = data.get("keywords", [])
        input_info = data.get("input", {})
        return PoCInfo(vuln_name, keywords, input_info)

    @classmethod
    def load_from_searched_target(cls, target_info):
        """Load PoCInfo from searched target"""
        vuln_name = target_info.vuln_name
        data = target_info.extra_info["poc_info"]
        return cls.load_from_json(vuln_name, data)
