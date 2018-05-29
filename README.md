# quickstart-microsoft-wapadfs
## Web Application Proxy on the AWS Cloud


This Quick Start deploys Web Application Proxy and Active Directory Federation Services (AD FS) on the AWS Cloud.

AD FS is a Windows Server role that authenticates users and provides security tokens to applications or federated partner applications that trust AD FS.

The Web Application Proxy role on Windows Server makes AD FS accessible to external users by proxying requests without requiring VPN connectivity. You can also use Web Application Proxy to selectively publish and pre-authenticate connections to internal web applications, allowing users outside your organization to access those applications over the Internet.

The Quick Start offers two deployment options:

- Deploying Web Application Proxy and AD FS into a new virtual private cloud (VPC) on AWS
- Deploying Web Application Proxy and AD FS into an existing VPC on AWS

You can also use the AWS CloudFormation templates as a starting point for your own implementation.

![Quick Start architecture for Web Application Proxy on AWS](https://d0.awsstatic.com/partner-network/QuickStart/datasheets/wap-adfs-architecture.png)

For architectural details, best practices, step-by-step instructions, and customization options, see the 
[deployment guide](https://fwd.aws/GmadX).

To post feedback, submit feature ideas, or report bugs, use the **Issues** section of this GitHub repo.
If you'd like to submit code for this Quick Start, please review the [AWS Quick Start Contributor's Kit](https://aws-quickstart.github.io/). 
