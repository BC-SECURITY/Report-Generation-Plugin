# Report Plugin
The report plugin replaces the original reporting tool in [Empire](https://github.com/BC-SECURITY/Empire/) and replaces it with customizable PDFs.
The current implemenation uses the style.css and templates to generate the reports with the option of using a personalized logo.

## Getting Started
* To run the plugin, you can download it fom the releases [Releases](https://github.com/BC-SECURITY/report-generation-plugin/releases) page. 

## Install
Prerequisites:
* Empire 3.2.3+
* [ATT&CK Plugin v0.1](https://github.com/BC-SECURITY/Attack-Plugin/releases)

1. Add report.py to the plugins folder of Empire.

![image](https://user-images.githubusercontent.com/20302208/86488866-45baf800-bd17-11ea-8605-f8bb9b081dda.png)

2. Add the Reports folder to the Empire directory.

![image](https://user-images.githubusercontent.com/20302208/86488897-61be9980-bd17-11ea-8edc-e43fa2be3a5d.png)

3. ```plugin report```

![image](https://user-images.githubusercontent.com/20302208/86488962-9af70980-bd17-11ea-90ce-831fdc3436e7.png)

4. ```report```

__Note:__ The Report Plugin replaces the original reporting funcationality.

![image](https://user-images.githubusercontent.com/20302208/86488991-bc57f580-bd17-11ea-8ac0-9b8ef62ec088.png)
