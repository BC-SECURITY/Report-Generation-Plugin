from __future__ import print_function

import threading
from jinja2 import Environment, FileSystemLoader
from tabulate import tabulate
from md2pdf.core import md2pdf
from sqlalchemy import or_, and_, func

from empire.server.plugins.MITRE_ATTACK import Plugin
from empire.server.database import models
from empire.server.database.base import Session
import empire.server.common.helpers as helpers


class Plugin(Plugin):
    description = "Generate enhanced reports and Markdown files for customized PDF reports"
    lock = threading.Lock()

    def onLoad(self):
        """
        any custom loading behavior - called by init, so any
        behavior you'd normally put in __init__ goes here
        """
        self.info = {
                        'Name': 'report',

                        'Author': ['@Cx01N'],

                        'Description': 'Generate enhanced reports and Markdown files for customized PDF reports',

                        'Software': '',

                        'Techniques': [''],

                        'Comments': []
                    },

        self.options = {
            'logo': {
                'Description': 'Provide directory to the logo on the teamserver.',
                'Required': True,
                'Value': './empire/server/Reports/Templates/empire.png'
            }
        }

    def execute(self, command):
        # This is for parsing commands through the api
        try:
            # essentially switches to parse the proper command to execute
            self.options['logo']['Value'] = command['logo']
            results = self.pdf_report('')
            return results
        except:
            return False

    def get_commands(self):
        return self.commands

    def register(self, mainMenu):
        """
        Any modifications to the mainMenu go here - e.g.
        registering functions to be run by user commands
        """
        mainMenu.__class__.pdf_report = self.pdf_report

    def pdf_report(self, *args):
        """
        Generate enhanced reports and Markdown files for customized PDF reports
        """

        self.logo = self.options['logo']['Value']
        print(helpers.color("[*] Generating Empire Report"))

        # Pull techniques and software used with Empire
        software, techniques = Plugin.attack_searcher(self)
        self.empire_report(self.logo, software, techniques)

        print(helpers.color("[*] Generating Session Report"))
        self.session_report(self.logo)

        print(helpers.color("[*] Generating Credentials Report"))
        self.credential_report(self.logo)

        print(helpers.color("[*] Generating Master Log"))
        self.master_log(self.logo)

        # Pull all techniques from MITRE database
        # TODO: Pull all software for module report
        techniques = Plugin.all_attacks(self)
        print(helpers.color("[*] Generating Module Report"))
        self.module_report(self.logo, software, techniques)

        print(helpers.color("[+] All Reports generated"))

    def shutdown(self):
        """
        if the plugin spawns a process provide a shutdown method for when Empire exits else leave it as pass
        """
        return

    def empire_report(self, logo_dir, software, techniques):
        self.lock.acquire()

        # Set info from database
        description = software['description']

        # Switch rows and columns of platforms
        platforms = software['x_mitre_platforms']
        platforms = [[platforms[j] for j in range(len(platforms))]]

        # Create list of techniques
        used_techniques = list([])
        for i in range(len(techniques)):
            used_techniques.append('<h3>' + techniques[i]['name'] + '</h3>')
            used_techniques.append(techniques[i]['description'])

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./empire/server/Reports/Templates/empire_report_template.md")

        # Add data to Jinja2 Template
        template_vars = {"logo": logo_dir,
                         "description": description,
                         "platforms": tabulate(platforms, tablefmt='html'),
                         "techniques": used_techniques}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./empire/server/Reports/Markdown/Empire_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD file
        md2pdf("./empire/server/Reports/Empire_Report.pdf", md_content=md_out, css_file_path='./empire/server/Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def session_report(self, logo_dir):
        self.lock.acquire()

        # Pull agent data from database
        agents = Session().query(models.Agent.session_id,
                                 models.Agent.hostname,
                                 models.Agent.username,
                                 models.Agent.checkin_time
                                 ).all()

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./empire/server/Reports/Templates/sessions_template.md")

        # Add headers for table
        sessions = [('SessionID', 'Hostname', 'User Name', 'First Check-in')]
        sessions.extend(agents)

        # Add data to Jinja2 Template
        template_vars = {"logo": logo_dir,
                         "sessions": tabulate(sessions, tablefmt='html')}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./empire/server/Reports/Markdown/Sessions_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD files)
        md2pdf("./empire/server/Reports/Sessions_Report.pdf", md_content=md_out, css_file_path='./empire/server/Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def credential_report(self, logo_dir):
        self.lock.acquire()

        # Pull agent data from database
        data = Session().query(models.Credential.domain,
                               models.Credential.username,
                               models.Credential.host,
                               models.Credential.credtype,
                               models.Credential.password
                               ).all()

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./empire/server/Reports/Templates/credentials_template.md")

        # Add headers for table
        creds = [('Domain', 'Username', 'Host', 'Cred Type', 'Password')]
        creds.extend(data)

        # Add data to Jinja2 Template
        template_vars = {"logo": logo_dir,
                         "creds": tabulate(creds, tablefmt='html')}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./empire/server/Reports/Markdown/Credentials_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD file
        md2pdf("./empire/server/Reports/Credentials_Report.pdf", md_content=md_out, css_file_path='./empire/server/Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def master_log(self, logo_dir):
        self.lock.acquire()
        data = self.run_report_query()

        # Format text as a string and print to new line
        log = ''
        for row in data:
            row = list(row)
            for n in range(len(row)):
                if isinstance(row[n], bytes):
                    row[n] = row[n].decode('UTF-8')
                if type(row[n]) == str:
                    row[n] = str(row[n]).replace('\n', ' <br> ')
            log = log + ' <br> ' + xstr(row[0]) + ' - ' + xstr(row[3]) + ' (' + xstr(row[2]) + ')> ' + xstr(
                row[5]) + xstr(row[6]) + xstr(row[7]) + ' <br> '

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./empire/server/Reports/Templates/masterlog_template.md")

        # Add data to Jinja2 Template
        template_vars = {"logo": logo_dir,
                         "log": log}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./empire/server/Reports/Markdown/Masterlog_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD file
        md2pdf("./empire/server/Reports/Masterlog_Report.pdf", md_content=md_out, css_file_path='./empire/server/Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def module_report(self, logo_dir, software, techniques):
        self.lock.acquire()

        # Pull agent data from database
        data = Session().query(models.Tasking.module_name.distinct()).filter(
            models.Tasking.module_name != None).all()

        ttp = list([])
        module_name = list([])
        for module_directory in data:
            try:
                ttp.append(self.mainMenu.modules.modules[module_directory[0]].info['Techniques'])
                module_name.append(self.mainMenu.modules.modules[module_directory[0]].info['Name'])
            except:
                continue

        # Create list of techniques
        used_techniques = list([])
        for ttp_list in ttp:
            for ttp_name in ttp_list:
                for i in range(len(techniques)):
                    if ttp_name in techniques[i]._inner['external_references'][0]._inner['external_id']:
                        try:
                            used_techniques.append('<h3>' + techniques[i]['name'] + '</h3>')
                            used_techniques.append(
                                '**Empire Modules Used:** ' + module_name[ttp.index(ttp_list)] + '<br><br>')
                            used_techniques.append(techniques[i]._inner['description'])
                        except:
                            pass

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./empire/server/Reports/Templates/module_report_template.md")

        log = ''
        # Add data to Jinja2 Template
        template_vars = {"logo": logo_dir,
                         "techniques": used_techniques}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./empire/server/Reports/Markdown/Module_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD file
        md2pdf("./empire/server/Reports/Module_Report.pdf", md_content=md_out, css_file_path='./empire/server/Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def run_report_query(self):
        reporting_sub_query = Session() \
            .query(models.Reporting, self.substring(Session(), models.Reporting.name, '/').label('agent_name')) \
            .filter(and_(models.Reporting.name.ilike('agent%'),
                         or_(models.Reporting.event_type == 'task',
                             models.Reporting.event_type == 'checkin'))) \
            .subquery()

        return Session() \
            .query(reporting_sub_query.c.timestamp,
                   reporting_sub_query.c.event_type,
                   reporting_sub_query.c.agent_name,
                   reporting_sub_query.c.taskID,
                   models.Agent.hostname,
                   models.User.username,
                   models.Tasking.input.label('task'),
                   models.Tasking.output.label('results')) \
            .join(models.Tasking, and_(models.Tasking.id == reporting_sub_query.c.taskID,
                                       models.Tasking.agent == reporting_sub_query.c.agent_name), isouter=True) \
            .join(models.User, models.User.id == models.Tasking.user_id, isouter=True) \
            .join(models.Agent, models.Agent.session_id == reporting_sub_query.c.agent_name, isouter=True) \
            .all()

    def substring(self, session, column, delimeter):
        """
        https://stackoverflow.com/a/57763081
        """
        if session.bind.dialect.name == 'sqlite':
            return func.substr(column, func.instr(column, delimeter) + 1)
        elif session.bind.dialect.name == 'mysql':
            return func.substring_index(column, delimeter, -1)

    def register(self, mainMenu):
        """
        Any modifications to the mainMenu go here - e.g.
        registering functions to be run by user commands
        """
        pass

    def shutdown(self):
        """
        Kills additional processes that were spawned
        """
        # If the plugin spawns a process provide a shutdown method for when Empire exits else leave it as pass
        pass


def xstr(s):
    """Safely cast to a string with a handler for None"""
    if s is None:
        return ''
    return str(s)
