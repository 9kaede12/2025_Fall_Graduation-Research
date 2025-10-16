# 2025 Fall Graduation Research

This repository hosts the research planning materials for the 2025 Fall
Graduation project. The current codebase is intentionally light-weight so new
contributors can set up the foundational workflows before expanding into data
collection, analysis, and reporting.

## Repository layout

The project is organized to keep research assets easy to locate and maintain.
As the work evolves, create the following top-level directories:

| Directory | Purpose |
| --- | --- |
| `docs/` | Background research notes, meeting minutes, experiment logs, and planning timelines. |
| `data/` | Raw and processed datasets. Keep large or sensitive files in external storage and reference them here. |
| `notebooks/` | Exploratory data analysis and prototype models in Jupyter or other notebook formats. |
| `src/` | Reusable analysis scripts, utilities, and production-ready code. |
| `reports/` | Drafts of papers, presentations, and visualizations for stakeholders. |

At the moment only this README is tracked, so the first task for new members is
to set up the folder structure that matches their planned contributions.

## Getting started

1. **Clone the repository.** Use SSH if you have write access or HTTPS if you
   do not.
2. **Create a feature branch.** Follow the convention `feature/<short-task>`
   or `research/<topic>` to keep history organized.
3. **Add project scaffolding.** Introduce the directories and starter files you
   need for your specific research stream.
4. **Document your decisions.** Keep the `docs/` folder updated with context,
   assumptions, and links to relevant references.
5. **Open a pull request early.** Share progress frequently to gather feedback
   from advisors and peers.

## Coding and documentation standards

- **Python preferred for analysis.** Use Python 3.11+ with type hints and
  follow [PEP 8](https://peps.python.org/pep-0008/) conventions.
- **Reproducibility matters.** Capture environment details in
  `requirements.txt` or a `environment.yml` file as soon as dependencies are
  introduced.
- **Data governance.** Never commit confidential or large raw datasets. Instead,
  add a README in `data/` describing how to obtain them.
- **Version control etiquette.** Keep commits focused, write descriptive commit
  messages, and rebase when necessary to maintain a clean history.

## Recommended next steps for new contributors

1. **Define the research question.** Align with project mentors on scope,
   expected outputs, and success criteria.
2. **Survey existing literature.** Summarize findings in `docs/literature.md`
   to avoid duplicating previous work.
3. **Plan the data pipeline.** Decide on sources, cleaning steps, and storage
   requirements before writing code.
4. **Prototype analyses.** Use notebooks to validate methods, then migrate
   stable logic into the `src/` directory.
5. **Set up continuous integration.** When code assets grow, configure testing
   (e.g., `pytest`) and linting (e.g., `ruff`) in a CI workflow.

## Communication and support

- **Weekly check-ins.** Share progress updates and blockers in the team’s
  designated channel or meeting.
- **Issue tracking.** Use GitHub Issues to log tasks, bugs, and ideas with clear
  ownership and due dates.
- **Pull request reviews.** Provide constructive feedback and request reviews
  when you are ready to merge.

Welcome aboard! Building a consistent structure now will make collaborative
research smoother as the 2025 Fall Graduation project grows.
