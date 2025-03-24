import io
import threading
from pathlib import Path
from typing import override

from jinja2 import Environment, FileSystemLoader
from md2pdf.core import md2pdf
from tabulate import tabulate

from empire.server.core.db import models
from empire.server.core.db.models import PluginTaskStatus
from empire.server.core.plugins import BasePlugin

from .mitre import Attack


class Plugin(BasePlugin):
    lock = threading.Lock()

    @override
    def on_load(self, db):
        self.execution_options = {
            "report": {
                "Description": "Report to generate by the server.",
                "Required": True,
                "Value": "all",
                "SuggestedValues": [
                    "all",
                    "empire",
                    "session",
                    "credential",
                    "master",
                    "module",
                ],
                "Strict": True,
            },
            "format": {
                "Description": "Format of the generated report.",
                "Required": True,
                "Value": "pdf",
                "SuggestedValues": ["md", "pdf"],
                "Strict": True,
            },
            # 'Logo': {
            #     'Description': 'Format of the generated report.',
            #     "Required": False,
            #     "Value": "",
            #     "SuggestedValues": [],
            #     "Strict": False,
            #     "Type": "file",
            # },
        }

        self.plugin_dir = Path(__file__).parent
        self.logo = str(self.plugin_dir / "templates" / "empire.png")
        self.Attack = Attack

    def execute(self, command, **kwargs):
        user = kwargs["user"]
        db = kwargs["db"]
        input = f"Generating reports for: {command['report']}"
        plugin_task = models.PluginTask(
            plugin_id=self.info.id,
            input=input,
            input_full=input,
            user_id=user.id,
            status=PluginTaskStatus.completed,
        )
        output = ""
        db_downloads = []

        # if self.options["Logo"] == "":
        #     self.logo = self.install_path + '/plugins/Report-Generation-Plugin/templates/empire.png'
        # else:
        #     print('test')

        report = command["report"]
        fmt = command["format"]
        if report in ["session", "all"]:
            db_download = self.session_report(db, user, fmt)
            db_downloads.append(db_download)
            output += f"[*] Session report generated to {db_download.location}\n"
        if report in ["empire", "all"]:
            db_download = self.empire_report(db, user, fmt)
            db_downloads.append(db_download)
            output += f"[*] Empire report generated to {db_download.location}\n"
        if report in ["credential", "all"]:
            db_download = self.credential_report(db, user, fmt)
            db_downloads.append(db_download)
            output += f"[*] Credential report generated to {db_download.location}\n"
        if report in ["master", "all"]:
            db_download = self.master_log(db, user, fmt)
            db_downloads.append(db_download)
            output += f"[*] Master report generated to {db_download.location}\n"
        if report in ["module", "all"]:
            db_download = self.module_report(db, user, fmt)
            db_downloads.append(db_download)
            output += f"[*] Module report generated to {db_download.location}\n"

        output += "[*] Execution complete.\n"
        plugin_task.output = output
        plugin_task.downloads = db_downloads
        db.add(plugin_task)
        db.flush()

    def generate_report(
        self, md_template: str, temp_var: dict, md_file: str, pdf_out: str, fmt: str
    ):
        """
        Generate pdf or markdown files using mustache templating
        """
        env = Environment(loader=FileSystemLoader(str(self.plugin_dir / "templates")))
        template = env.get_template(md_template)

        # Save markdown to file, if it requires editing
        md_out = template.render(temp_var)
        with open(md_file, "w") as f:
            f.write(md_out)

        if fmt == "pdf":
            # Generate PDF from MD file
            md2pdf(
                pdf_out,
                md_content=md_out,
                css_file_path=str(self.plugin_dir / "templates" / "style.css"),
                base_url=".",
            )
            return pdf_out
        if fmt == "md":
            return md_file
        raise ValueError("Invalid format")

    def empire_report(self, db, user, fmt):
        # Pull techniques and software used with Empire
        software, techniques = self.Attack(self.main_menu).attack_searcher()

        # Set info from database
        description = software["description"]

        # Switch rows and columns of platforms
        platforms = software["x_mitre_platforms"]
        platforms = [[platforms[j] for j in range(len(platforms))]]

        # Create list of techniques
        used_techniques = list([])
        for i in range(len(techniques)):
            used_techniques.append("<h3>" + techniques[i]["name"] + "</h3>")
            used_techniques.append(techniques[i]["description"])

        # Add data to Jinja2 Template
        template_vars = {
            "logo": self.logo,
            "description": description,
            "platforms": tabulate(platforms, tablefmt="html"),
            "techniques": used_techniques,
        }

        return self.generate_and_upload_report(
            db, user, template_vars, "Empire_Report", fmt
        )

    def session_report(self, db, user, fmt):
        sessions = [
            (
                session.session_id,
                session.hostname,
                session.username,
                session.firstseen_time,
            )
            for session in db.query(models.Agent).all()
        ]
        sessions.insert(0, ("SessionID", "Hostname", "User Name", "First Check-in"))

        template_vars = {
            "logo": self.logo,
            "sessions": tabulate(sessions, tablefmt="html"),
        }

        return self.generate_and_upload_report(
            db, user, template_vars, "Sessions_Report", fmt
        )

    def credential_report(self, db, user, fmt):
        creds = [("Domain", "Username", "Host", "Cred Type", "Password")]
        for row in db.query(models.Credential).all():
            creds.extend(
                [row.domain, row.username, row.host, row.credtype, row.password]
            )

        # Add data to Jinja2 Template
        template_vars = {"logo": self.logo, "creds": tabulate(creds, tablefmt="html")}

        return self.generate_and_upload_report(
            db, user, template_vars, "Credentials_Report", fmt
        )

    def master_log(self, db, user, fmt):
        out = io.StringIO()
        out.write("=" * 50 + "\n\n")
        for row in db.query(models.AgentTask).all():
            row: models.AgentTask
            username = row.user.username if row.user else "None"
            out.write(
                f"\n{xstr(row.created_at)} - {xstr(row.id)} ({xstr(row.agent_id)})> "
                f"{xstr(username)}\n {xstr(row.input)[:100]}\n {xstr(row.output)[:1000]}\n"
            )

        output_str = out.getvalue()

        # Add data to Jinja2 Template
        template_vars = {"logo": self.logo, "log": output_str}

        return self.generate_and_upload_report(
            db, user, template_vars, "Masterlog_Report", fmt
        )

    def module_report(self, db, user, fmt):
        # TODO: Pull all software for module report
        # software, techniques = self.Attack(self.main_menu).attack_searcher()

        # Pull all techniques from MITRE database
        techniques = self.Attack(self.main_menu).all_attacks()

        # Pull task data from database
        data = db.query(models.AgentTask).all()

        ttp = list([])
        module_name = list([])
        for task in data:
            try:
                module_name.append(
                    self.main_menu.modulesv2.modules[task.module_name].name
                )
                ttp.append(
                    self.main_menu.modulesv2.modules[task.module_name].techniques
                )
            except KeyError:
                pass

        # Create list of techniques
        used_techniques = list([])
        for ttp_list in ttp:
            for ttp_name in ttp_list:
                for i in range(len(techniques)):
                    if (
                        ttp_name
                        in techniques[i]
                        ._inner["external_references"][0]
                        ._inner["external_id"]
                    ):
                        try:
                            used_techniques.append(
                                "<h3>" + techniques[i]["name"] + "</h3>"
                            )
                            used_techniques.append(
                                "**Empire Modules Used:** "
                                + module_name[ttp.index(ttp_list)]
                                + "<br><br>"
                            )
                            used_techniques.append(techniques[i]._inner["description"])
                        except:
                            pass

        # Add data to Jinja2 Template
        template_vars = {"logo": self.logo, "techniques": used_techniques}

        return self.generate_and_upload_report(
            db, user, template_vars, "Module_Report", fmt
        )

    def generate_and_upload_report(self, db, user, template_vars, report_name, fmt):
        pdf_out = self.plugin_dir / f"{report_name}.pdf"
        md_out = self.plugin_dir / "markdown" / f"{report_name}.md"

        self.generate_report(
            md_template=f"{report_name.lower()}_template.md",
            temp_var=template_vars,
            md_file=str(md_out),
            pdf_out=str(pdf_out),
            fmt=fmt,
        )

        test_upload = self.plugin_dir / f"{report_name}.pdf"
        db_download = self.main_menu.downloadsv2.create_download(db, user, test_upload)

        return db_download


def xstr(s):
    """
    Safely cast to a string with a handler for None
    """
    if s is None:
        return ""
    return str(s)
