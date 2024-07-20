from dataclasses import dataclass, field, fields
import enum
import json

from .result import ResultKey, ResultSet


class GroundTruthResult(enum.Enum):
    """
    Result of groundtruth item
    """

    NOT_VULN = 0
    VULN = 1
    POSSIBLE = 2

    @classmethod
    def parse(cls, name: str):
        return cls._member_map_.get(name.upper())


@dataclass
class GroundTruth:
    """
    GroundTruth set for result verification
    """

    result_dict: dict[ResultKey, GroundTruthResult] = field(default_factory=dict)

    @classmethod
    def load(cls, gt_path):
        """
        Load groundtruth from file
        """
        with open(gt_path, "r") as fp:
            gt_raw = json.load(fp)

        results = {}
        for gt_item in gt_raw:
            res_raw = gt_item.pop("gt")
            res = GroundTruthResult.parse(res_raw)
            attrs = [field.name for field in fields(ResultKey)]
            for attr in attrs:
                if attr not in gt_item:
                    gt_item[attr] = None
            key = ResultKey(**gt_item)
            results[key] = res

        return cls(results)

    def verify(self, resset: ResultSet):
        """
        Verify firmrec result with groundtruth

        :param resset: firmrec result to verify
        :return: generator of FirmRecResultKey, GroundTruthResult pairs
        """
        for key, gt in self.items():
            for res in resset.find_results(**key.to_dict()):
                yield res.key, gt

    def keys(self):
        return self.result_dict.keys()

    def values(self):
        return self.result_dict.values()

    def items(self):
        return self.result_dict.items()

    def update(self, another):
        if not isinstance(another, GroundTruth):
            raise ValueError(repr(another), "Is not instanece of GroundTruth")
        self.result_dict.update(another.result_dict)

    def __contains__(self, key):
        return key in self.result_dict

    def __getitem__(self, key):
        return self.result_dict[key]

    def __setitem__(self, key, result):
        self.result_dict[key] = result

    def __iter__(self):
        return self.result_dict.__iter__()

    def __repr__(self) -> str:
        return f"<GroundTruth @ {id(self)}>"

    def __str__(self) -> str:
        return self.__repr__()
