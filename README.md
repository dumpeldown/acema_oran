
# Custom ACEMA Sources for Open RAN Security Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

(see [German version](#benutzerdefinierte-acema-quellen-für-das-open-ran-security-dashboard))

This repository contains a customized version of source code specifically tailored for the requirements of my Bachelor's thesis:

**"Implementation of a Dashboard for Pentesting in a Digital Forensics and Incident Response (DFIR) Environment for Open RAN".**

For the original files and base code, please refer to the original repository: [https://github.com/fklement/acema_oran](https://github.com/fklement/acema_oran).

## Objective of the Thesis

The goal of this thesis was to develop a dashboard that enables comprehensive security assessments of Open RAN systems. The implementation is based on the **ACEMA method** and integrates features such as **CVSS scoring** and dynamic visualizations.

The dashboard provides:
- Support for pentesting scenarios in Open RAN environments.
- Detailed vulnerability analysis by linking attack paths with known security vulnerabilities (CVE).
- Evaluation of techniques and individual attacks using CVSS.

The results of this work demonstrate the effectiveness of the dashboard as a tool for security analysis in Open RAN environments and its practical relevance for DFIR applications.

---

### Integration of the ACEMA Method

The source codes of the empirical **ACEMA method** have been specifically adapted to meet the requirements of this work.

## Quickstart

### Steps to Reproduce
1. **Data collection:**
   - Run `data_gathering_nb.py` to collect relevant vulnerability data.
2. **Perform analysis:**
   - Use `data_analysis_nb.py` to analyze the data and create diagrams.

---

## References

- **Study: "Towards Securing the 6G Transition: A Comprehensive Empirical Method to Analyze Threats in O-RAN Environments"**.
- Additional works within the scope of the 5G-FORAN project (currently closed-source, more information at [the website](https://www.5g-foran.com/)):
  - Implementation of a framework for generating attack traces.
  - Development of a dashboard prototype.
- LaTeX project for my Bachelor's thesis [here](https://github.com/dumpeldown/foran-ba)

--------------
--------------


# Benutzerdefinierte ACEMA-Quellen für das Open RAN Security Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Diese Repository enthält die Quellcodes, die ich im Rahmen meiner Bachelorarbeit verwende:

**"Implementierung eines Dashboards für Pentesting in einer Digital Forensics and Incident Response (DFIR) Umgebung für Open RAN".**

Für die Originaldateien und den Basiscode verweisen wir auf das ursprüngliche Repository: [https://github.com/fklement/acema_oran](https://github.com/fklement/acema_oran).

## Ziel der Arbeit

Das Ziel dieser Arbeit war die Entwicklung eines Dashboards, das eine umfassende Sicherheitsbewertung von Open RAN-Systemen ermöglicht. Die Implementierung baut auf der **ACEMA-Methode** auf und integriert Features wie **CVSS-Bewertungen** und dynamische Visualisierungen.

Das Dashboard bietet:
- Unterstützung für Pentesting-Szenarien in Open RAN-Umgebungen.
- Detaillierte Schwachstellenanalyse durch die Verknüpfung von Angriffspfaden mit bekannten Sicherheitslücken (CVE).
- Bewertung von Techniken und einzelnen Angriffen mithilfe des CVSS.

Die Ergebnisse dieser Arbeit belegen die Wirksamkeit des Dashboards als Werkzeug für Sicherheitsanalysen in Open RAN-Umgebungen und seine praktische Relevanz für DFIR-Anwendungen.

---

### Integration der ACEMA-Methode
Die Quellcodes der empirischen Methode **ACEMA** wurden speziell angepasst, um die Anforderungen der Arbeit zu erfüllen.
---

## Quickstart

### Schritte zur Reproduktion
1. **Daten sammeln:**
   - Führen Sie `data_gathering_nb.py` aus, um relevante Schwachstellendaten zu sammeln.
2. **Analyse durchführen:**
   - Verwenden Sie `data_analysis_nb.py`, um die Daten zu analysieren und Diagramme zu erstellen.

---

## Referenzen

- **Studie: "Towards Securing the 6G Transition: A Comprehensive Empirical Method to Analyze Threats in O-RAN Environments"** .
- Weiterführende Arbeiten im Rahmen des Projekts 5G-FORAN, darunter: (aktuell closed-source, weitere Infos auf [der Website](https://www.5g-foran.com/))
  - Implementierung eines Frameworks für Angriffsspuren.
  - Entwicklung einer Dashboard-Prototypen.
- Latex-Projekt meiner Bachelorarbeit [hier](https://github.com/dumpeldown/foran-ba)


