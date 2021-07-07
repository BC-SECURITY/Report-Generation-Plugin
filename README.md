# Report Plugin
The report plugin replaces the original reporting functionality in [Empire](https://github.com/BC-SECURITY/Empire/) with
customizable PDFs. The PDFs use a style.css and Jinja2 template markdown files to generate the PDF reports. The style.css
and markdown files can be customized with personalized logos or other information. The reports use the 
[ATT&CK Plugin](https://github.com/BC-SECURITY/Attack-Plugin/releases) to generate two tailored reports: Empire Report 
and Module Report. The Empire Report parses out the information about Empire and creates a PDF about the attack techniques 
based on the MITRE ATT&CK framework. The Module Report uses the master log to extract all of the used modules and creates
individual sections based on the modules used. Examples of the reports can be found [here](./Reports/README.md).

## Install
* To run the plugin, you can download it fom the releases [Releases](https://github.com/BC-SECURITY/Attack-Plugin/releases) page. 

Prerequisites:
- Empire 3.7.0+
- MD2PDF
- [ATT&CK Plugin v1.0](https://github.com/BC-SECURITY/Attack-Plugin/releases)

1. Add report.py to the plugins folder of Empire.

![image](https://user-images.githubusercontent.com/20302208/86488866-45baf800-bd17-11ea-8605-f8bb9b081dda.png)

2. Add the Reports folder to the Empire directory.

![image](https://user-images.githubusercontent.com/20302208/86488897-61be9980-bd17-11ea-8edc-e43fa2be3a5d.png)

3. Install MD2PDF: `sudo poetry add md2pdf`

## Usage
### Client
![empire_report](https://user-images.githubusercontent.com/20302208/122622654-36c77580-d04e-11eb-81fa-d0acc0ac5ece.gif)

