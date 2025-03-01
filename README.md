# Advanced Reporting Plugin
The report plugin replaces the original reporting functionality in [Empire](https://github.com/BC-SECURITY/Empire/) with
customizable PDFs and Markdown files. The PDFs use a style.css and Jinja2 template markdown files to generate the PDF reports. The style.css
and markdown files can be customized with personalized logos or other information. The reports use MITRE ATT&CK to generate two tailored reports: Empire Report 
and Module Report. The Empire Report parses out the information about Empire and creates a PDF about the attack techniques 
based on the MITRE ATT&CK framework. The Module Report uses the master log to extract all of the used modules and creates
individual sections based on the modules used. Examples of the reports can be found [here](./templates/README.md).

<img width="776" alt="image" src="https://github.com/BC-SECURITY/Empire/assets/20302208/9f1d81a3-6bdc-4d65-a450-35ac3e19c264">

## Prerequisites
- Empire >=6.0
- MD2PDF
- Tabulate

## Install

Install via Starkiller's plugin marketplace.
It also requires the following packages to be installed on the Empire server.

```bash
poetry add md2pdf tabulate
```
