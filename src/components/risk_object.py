COLOR_RATING = {
    "red" : "\033[31m",
    "yel" : "\033[33m",
    "cyan" : "\033[36m",
    "reset" :  "\033[0m"
}

class RiskObject:
    __slots__ = ["__kev_status","__epss_score","__cvss_score"
    , "__cve_id", "__severity_rating","__description",]

    def __init__(self,cve_id: str,description: str = "",cvss_score: float = 0.0,epss_score: float = 0.0,
                severity_rating: float = 0.0, 
                kev_status: bool = False):
        self.__cve_id = cve_id
        self.__description = description
        self.__cvss_score = cvss_score
        self.__severity_rating = severity_rating
        self.__epss_score = round(epss_score * 100, 2)
        self.__kev_status = kev_status

    def repr_severity_level(self):
        if self.__severity_rating >= 9.0:
            return f"{COLOR_RATING.get("red")} CRITICAL{COLOR_RATING.get("reset")}"
        if self.__severity_rating >= 7.0:
            return f"{COLOR_RATING.get("red")} ACCELERATED {COLOR_RATING.get("reset")}"
        if self.__severity_rating >= 4.0:
            return f"{COLOR_RATING.get("yel")} ROUTINE {COLOR_RATING.get("reset")}"
        else:
            return f"{COLOR_RATING.get("cyan")} ROUTINE {COLOR_RATING.get("reset")}"

    def assess_risk(self) -> float:
        cvss_weight = 0.5
        cvss_score = self.__cvss_score * cvss_weight
        epss_weight = 0.4
        epss_score = self.__epss_score * epss_weight
        kev_weight = 0.1
        kev_score = 0
        if self.__kev_status:
            kev_score = kev_weight * 10
        self.__severity_rating = kev_score + cvss_score + epss_score
    def __str__(self) -> str:
        return (
            f"CVE: {self.__cve_id}\n"
            f"Description: {self.__description}\n"
            f"CVSS Score: {self.__cvss_score}\n"
            f"EPSS Score: {self.__epss_score}\n"
            f"KEV Status: {self.__kev_status}\n"
            f"Risk Assessment: {self.repr_severity_level()}\n"
            f"Risk Score: {self.__severity_rating}\n"
    )
