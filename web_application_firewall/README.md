<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/capstone-g41-waf-ids/">
    <img src="../documentation-images/capstonelogorectangle.png" alt="Logo" width="600" height="300">
  </a>
</div>
<h3 align="center">Web Application Firewall</h3>

  <p align="center">
    Swinburne 2022 Capstone Group 41 Project
    <br />
    <br />

  </p>


<!-- USAGE EXAMPLES -->
## The Web Application Firewall Folder

This folder contains files that are used to generate the NGINX reverse proxy and the WAF. <br><br>
In the base folder there is:<br>
<li>country_codes which attributes a country code to the country's full name</li>
<li>docker-entrpoint.sh is responsible for loading the services: nginx, flask, pyopenssl onto the container</li>
<li>dockerfile, which provides additional configurations to the WAF container outside the docker-compose file</li>
<li>flask_webserver.py which is responsible for running the WAF configuration portal</li>
<br> Inside the portal folder is the templates, static pages and uwsgi.ini file use to build the portal.
<br> and finally the etc folder contains the modsecurity rules and configurations and the nginx configuration. 

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [Roy](https://github.com/orgs/capstone-g41-waf-ids/people/RoystonJoel)
* [Ellen](https://github.com/orgs/capstone-g41-waf-ids/people/orangeblossomest)
* [Tom](https://github.com/orgs/capstone-g41-waf-ids/people/Choski)
* [Fuman](https://github.com/orgs/capstone-g41-waf-ids/people/fumank2)
* [Darcy](https://github.com/orgs/capstone-g41-waf-ids/people/ASD-Database)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

