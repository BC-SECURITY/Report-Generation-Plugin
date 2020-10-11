# Report Plugin
The report plugin replaces the original reporting functionality in [Empire](https://github.com/BC-SECURITY/Empire/) with
customizable PDFs. The PDFs use a style.css and Jinja2 template markdown files to generate the PDF reports. The style.css
and markdown files can be customized with personalized logos or other information. The reports use the 
[ATT&CK Plugin](https://github.com/BC-SECURITY/Attack-Plugin/releases) to generate two tailored reports: Empire Report 
and Module Report. The Empire Report parses out the information about Empire and creates a PDF about the attack techniques 
based on the MITRE ATT&CK framework. The Module Report uses the master log to extract all of the used modules and creates
individual sections based on the modules used. Examples of the reports can be found [here](./Reports/README.md).

## Getting Started
* To run the plugin, you can download it fom the releases [Releases](https://github.com/BC-SECURITY/report-generation-plugin/releases) page. 

## Install
Prerequisites:
* Empire 3.2.3+
* MD2PDF
* [ATT&CK Plugin v0.1](https://github.com/BC-SECURITY/Attack-Plugin/releases)

```
pip3 install md2pdf
```

1. Add report.py to the plugins folder of Empire.

![image](https://user-images.githubusercontent.com/20302208/86488866-45baf800-bd17-11ea-8605-f8bb9b081dda.png)

2. Add the Reports folder to the Empire directory.

![image](https://user-images.githubusercontent.com/20302208/86488897-61be9980-bd17-11ea-8edc-e43fa2be3a5d.png)

3.  Plugins are automatically loaded into Empire as of 3.4.0, otherwise run ```plugin report```

![image](https://user-images.githubusercontent.com/20302208/86488962-9af70980-bd17-11ea-90ce-831fdc3436e7.png)

4. ```report```

__Note:__ The Report Plugin replaces the original reporting funcationality.

![image](https://user-images.githubusercontent.com/20302208/86488991-bc57f580-bd17-11ea-8ac0-9b8ef62ec088.png)
