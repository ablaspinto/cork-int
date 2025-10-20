# CVE Prioritization CLI - Tool

## Instructions 
TBD


## Assignment 
Build a CLI Tool that fetches the latest vulnerabilites and assigns a severity rating based on the CVSS, EPSS Score, if it is a KEV 

### Work Flow Diagram

![Initial workflow diagram](work_flow_diagram.png "CVE Prioritization Workflow")


### Severity Rating Calculation Reasoning
- Critical
  - KEV 
    - it is a critical severity rating as these are common  vulnerabilities that can be exploited.

  - CVSS Rating >= 9.0 && EPSS Score >= 50% 
      - Has a high level for possible software vulnerabilities as well as may has a 50% chance within the next 30 days
  - CVSS Rating >= 7.0 && EPSS Score >= 70% 
      - Has an above average score on software vulnerabilities as well as contains a very high likelihood of being exploited over the next 30 days according to the EPSS Score
- Accelerated
  - CVSS Rating >= 8.0 && EPSS Score >= 30%
      - Has a score High of being a potential Threat, and with a EPSS score that has potential to happen within the month
  - CVSS Rating >= 7.0-7.9 && EPSS Score 40%-70%
      - Has a high CVSS score to potentially become a greater threat as the EPSS Score has a threat to possibly occur this month 
  - CVSS Rating >= 6.0 && EPSS >= 60%
      - While the rating for CVSS Score is moderate, the EPSS score has a change greater than a coin flip to happen within the next 30 days
- Routine 
  - CVSS Rating 7.0-7.9 and EPSS Score <40%
    - While it may have a High score, it has less than a coin flip chance to occur within the month so it should still be monitered.
  - CVSS Rating 5.0-6.9 and EPSS 30%-60%
    - Has a Medium CVSS Score and potentially less than or greater than 50% change of occuring within the month, however if it is monitered it should be fine
  - CVSS Rating >= 7.0 and EPSS <= 10%
    - Has a low likelihood of occuring within the month while, the rating is high, and should be monitered we should also take into account what resources we want to spend on low risk.
  










