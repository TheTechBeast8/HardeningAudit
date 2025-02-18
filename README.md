
## Hardening-Audit:
  Hardening-Audit provides deployment and auditing scripts for CIS (Center for Internet Security) Benchmarks,
  designed to help individuals and organizations ensure compliance with best security practices.
  These scripts automate the process of auditing against and deploying CIS benchmarks. Currently, I only have plans to have a deployment script for the registry items (for those who want them) and an audit script.
  I have no plans currently to create a complex HTML report that tells you exactly which controls are enabled versus which are disabled, but rather just a percentage output per section and total.
  These scripts were made primarily for my use case but I felt like I should share them as others may find them useful.

  I am new to using GitHub so please keep that in mind. I also am pretty new to scripting and realize my scripts are pretty busy and rudimentary but I wanted it to all be contained in 1 file. I am open to any feedback or suggestions you may have to help me grow. Please use the discussions if you would like to discuss something with me.
## Use Case:
  Currently, I am deploying these scripts to my devices in tiers to test for issues amongst my devices, then will "enforce" the settings with the GPO settings. There are some controls that my organization deems "not necessary" and we have chosen to modify these scripts to fit our needs but the scripts provided are unmodified and exactly match the CIS benchmark 
  recommendations. I encourage you to review them and test them accordingly for your organization and see if you should disable any. We then use our RMM tool to deploy them directly to the workstations. The audit script is used to assess the CIS Benchmark compliance percentage. Only want L1 keys that might be 70% total compliance, etc.
  If that sounds similar to your use case this should work wonders for you. Otherwise, I encourage you to take it, modify it, or fork it so that others may use it.

## Usage:
  Currently, the scripts are meant to be used with an RMM platform that allows you to schedule and script jobs or as stand-alone scripts. The deployment scripts do not apply any GPO-specific changes, but the audit script does check for them.

  There are several things that you may or may not need.
  GPOs - GPOs to delploy the CIS standards are located in the related versions GPO folder. You can get into group policy manager and restore them from backup
  Deployments scripts - if you prefer to deploy them via scripts i have those in the related version Deployment Scripts folder.
  Reports - The report to show you your compliance score and to tell you what configurations are missing.

## Finished Benchmarks/Audits:
  - CIS Microsoft Windows 10 Stand-alone Benchmark v3.0.0
  - CIS Microsoft Windows 11 Stand-alone Benchmark v3.0.0
## In Progress Benchmarks/Audits:
  - CIS Microsoft Server 2019 Benchmark v3.0.1
## Planned Benchmarks/Audits:
  - CIS Microsoft Server 2022 Benchmark v3.0.0
## Contributing:
  Contributions are welcome! If you'd like to improve the scripts, add support for new platforms, 
  or report issues, please feel free to submit a pull request or open an issue.
  ### Guidelines:
  - Submit pull requests for new features or bug fixes
  - Open issues for bugs, improvements, or suggestions
## Disclaimer: 
  The files and scripts provided in this repository are based on the CIS (Center for Internet Security) Benchmarks and are intended to assist with auditing and hardening systems according to these best practices. However, these scripts are provided as-is and should be reviewed and tested by each user in their own environment before deployment.
  It is the responsibility of the user to modify the scripts according to their specific requirements, system configurations, and security needs. By using these files, you acknowledge that the scripts may not fully cover every scenario or configuration, and I cannot guarantee that they will be suitable for all environments.
  I am not liable for any direct or indirect damages, security incidents, or operational problems that may result from the use or misuse of these scripts. Please ensure that you thoroughly evaluate any changes before implementing them in production environments.

  By downloading these files, you agree to this disclaimer.
## Thank You:
  Thank you for using Hardening-Audit! Your feedback and contributions are highly valued, and 
  I hope these scripts help make your systems more secure and compliant.
