
class Technology:
    def __init__(self, framework_name: str, version: str):
        self.framework_name = framework_name
        self.version = version


class Cve:
    def __init__(self, technology: Technology, cve_name: str, description: str):
        self.technology = technology
        self.cve_name = cve_name
        self.description = description
