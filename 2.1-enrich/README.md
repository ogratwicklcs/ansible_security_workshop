# Exercise 2.1 - Investigation Enrichment

## Step 1.1 - The Background

In the last section the focus was on single tools and how they can be automated with Ansible. In the daily operation of security practitioners the need is one step higher: when something suspicious happens and needs further attention, security operations need to deploy many tools to secure an enterprise IT. In many enterprise environments, security solutions are not integrated with each other and, in large organizations, different teams are in charge of different aspects of IT security, with no processes in common. That often leads to manual work and interaction between people of different teams which is error prone and above all, slow.

In comes Ansible: we use Ansible to elevate the interactions learned in the last section to combine the security tools into automated workflows.

## Step 1.2 - Preparations

For this exercise to work properly, the playbook `whitelist_attacker.yml` must have been run at least once. Also the logging for the attacker whitelist policy must have been activated. Both was done in the Check Point exercise. If you missed the steps, go back there, execute the playbook, follow the steps to activate the logging and come back here.

Also we need the QRadar collection. This was installed already in the previous QRadar exercise. If you missed that part, install them via: `ansible-galaxy collection install ibm.qradar`

Addtionally we will use the role to modify IDS rules from the previous Snort exercise. If you missed that, install them via: `ansible-galaxy install ansible_security.ids_rule`

Next, since this is a security lab, we do need suspicious traffic - an attack. We have a playbook which simulates a simple access every five seconds on which the other components in this exercise will later on react to. In your VS Code online editor, create the playbook `web_attack_simulation.yml` in the user home directory with the following content:

<!-- {% raw %} -->
```yml
---
- name: start attack
  hosts: attacker
  become: yes
  gather_facts: no

  tasks:
    - name: simulate attack every 5 seconds
      shell: "/sbin/daemonize /usr/bin/watch -n 5 curl -m 2 -s http://{{ hostvars['snort']['private_ip2'] }}/web_attack_simulation"
```
<!-- {% endraw %} -->

Execute the playbook:

```bash
[student<X>@ansible ansible-files]$ ansible-playbook web_attack_simulation.yml
```

> **Note**
>
> Basically in this playbook we register a small daemon running watch, which will execute a command every 5 seconds. This is a rather harsh way to start a repeating task, but serves the purpose of this lab.

## Step 1.3 - Write playbook to create new log sources

If you use a SIEM, things are better: you can collect and analyze logs centrally. In our case the SIEM is QRadar. QRadar has the ability to collect logs from other systems and search them for suspicious activities. So how do we analyze logs in QRadar? Before we can look at these logs we need to stream them into QRadar. This happens in two steps: first we need to configure the sources - here Check Point and Snort - to forward their logs to QRadar. And second we have to add those systems as log sources to QRadar.

Doing this manually requires a lot of work on multiple machines, which again takes time and might require privileges a security analyst does not have. But Ansible allows security organizations to create pre-approved automation workflows in the form of playbooks. 

So let's write such a playbook which first configures the log sources - Snort and Check Point - to send the logs to QRadar, and afterwards add those log sources to QRadar so that it is aware of them.

Let's start with the Snort configuration. We need Snort's log server to send the logs to the QRadar server. This can be configured with an already existing role, [ids_config](https://github.com/ansible-security/ids_config), so all we have to do is to import the role and use it with the right parameters.

In a terminal of your VS Code online editor, use the `ansible-galaxy` tool to download and install the above mentioned role with a single command:

```bash
[student<X>@ansible ~]$ ansible-galaxy install ansible_security.ids_config
- downloading role 'ids_config', owned by ansible_security
- downloading role from https://github.com/ansible-security/ids_config/archive/master.tar.gz
- extracting ansible_security.ids_config to /home/student<X>/.ansible/roles/ansible_security.ids_config
- ansible_security.ids_config (master) was installed successfully
```

So let's create our playbook where we use the role. In your VS Code online editor, create the file `enrich_log_sources.yml` with the following content:

<!-- {% raw %} -->
```yaml
---
- name: Configure snort for external logging
  hosts: snort
  become: true
  vars:
    ids_provider: "snort"
    ids_config_provider: "snort"
    ids_config_remote_log: true
    ids_config_remote_log_destination: "{{ hostvars['qradar']['private_ip'] }}"
    ids_config_remote_log_procotol: udp
    ids_install_normalize_logs: false

  tasks:
    - name: import ids_config role
      include_role:
        name: "ansible_security.ids_config"
```
<!-- {% endraw %} -->

As you see, just like with the last time we configured Snort rules, we are re-using the role and let it do the work. We only change the behaviour of the role via the parameters: we provide the QRadar IP via variable, set the IDS provider to `snort` and define the protocol in which packages are sent as `UDP`

Now we have to tell QRadar that there is this new Snort log source. Add the following play to the playbook `enrich_log_sources.yml`:

<!-- {% raw %} -->
```yaml
- name: Add Snort log source to QRadar
  hosts: qradar
  collections:
    - ibm.qradar

  tasks:
    - name: Add snort remote logging to QRadar
      qradar_log_source_management:
        name: "Snort rsyslog source - {{ hostvars['snort']['private_ip'] }}"
        type_name: "Snort Open Source IDS"
        state: present
        description: "Snort rsyslog source"
        identifier: "{{ hostvars['snort']['private_ip']|regex_replace('\\.','-')|regex_replace('^(.*)$', 'ip-\\1') }}"
```
<!-- {% endraw %} -->

As you can see the collections are used here, and the only task we execute uses a module to manage log sources in QRadar. You might ask what the regex is doing in there: it changes the IP address to match the actual syslog header entry produced by Snort. Otherwise, the logs would not be properly identified by QRadar.

Now we have to do the same for Check Point: we need to configure Check Point to forward its logs to QRadar. This can be configured with an already existing role, [log_manager](https://github.com/ansible-security/log_manager), so all we have to do is to import the role and use it with the right parameters. First, let's import the role:

```bash
[student<X>@ansible ~]$ ansible-galaxy install ansible_security.log_manager
- downloading role 'log_manager', owned by ansible_security
- downloading role from https://github.com/ansible-security/log_manager/archive/master.tar.gz
- extracting ansible_security.log_manager to /home/student<X>/.ansible/roles/ansible_security.log_manager
- ansible_security.log_manager (master) was installed successfully
```

Now edit again the existing playbook `enrich_log_sources.yml` where we already brought together Snort and QRadar, and add another section for Check Point:

<!-- {% raw %} -->
```yaml
- name: Configure Check Point to send logs to QRadar
  hosts: checkpoint

  tasks:
    - include_role:
        name: ansible_security.log_manager
        tasks_from: forward_logs_to_syslog
      vars:
        syslog_server: "{{ hostvars['qradar']['private_ip'] }}"
        checkpoint_server_name: "YOURSERVERNAME"
        firewall_provider: checkpoint
```
<!-- {% endraw %} -->

Note that in this snippet you have to replace `YOURSERVERNAME` with the actual server name from your Check Point management instance, like `gw-77f3f6`. You can find the name of your individual Check Point instance by logging into your SmartConsole. It is shown in the **GATEWAYS & SERVERS** tab in the lower part of the screen underneath **Summary**:

![Check Point Gateway Name](images/check_point_gw_name.png)

Replace the string `YOURSERVERNAME` in the playbook with your indididual name.

> **Note**
>
> This could also be done automatically with two API calls, but it would complicate the playbook listing here.

Now we have to tell QRadar that there is another log source, this time Check Point. Add the following play to the playbook `enrich_log_sources.yml`:

<!-- {% raw %} -->
```yaml
- name: Add Check Point log source to QRadar
  hosts: qradar
  collections:
    - ibm.qradar

  tasks:
    - name: Add Check Point remote logging to QRadar
      qradar_log_source_management:
        name: "Check Point source - {{ hostvars['checkpoint']['private_ip'] }}"
        type_name: "Check Point FireWall-1"
        state: present
        description: "Check Point log source"
        identifier: "{{ hostvars['checkpoint']['private_ip'] }}"

    - name: deploy the new log source
      qradar_deploy:
        type: INCREMENTAL
      failed_when: false
```
<!-- {% endraw %} -->

Note that compared to the last QRadar play, this time an additional task is added: `deploy the new log source`. This is due to the fact that QRadar changes are spooled, and only applied upon an extra request. We ignore errors because they might happen due to timeouts in the REST API which do not inflict the actual function of the API call.

If you bring all these pieces together, the full playbook `enrich_log_sources.yml` is:

<!-- {% raw %} -->
```yaml
---
- name: Configure snort for external logging
  hosts: snort
  become: true
  vars:
    ids_provider: "snort"
    ids_config_provider: "snort"
    ids_config_remote_log: true
    ids_config_remote_log_destination: "{{ hostvars['qradar']['private_ip'] }}"
    ids_config_remote_log_procotol: udp
    ids_install_normalize_logs: false

  tasks:
    - name: import ids_config role
      include_role:
        name: "ansible_security.ids_config"

- name: Add Snort log source to QRadar
  hosts: qradar
  collections:
    - ibm.qradar

  tasks:
    - name: Add snort remote logging to QRadar
      qradar_log_source_management:
        name: "Snort rsyslog source - {{ hostvars['snort']['private_ip'] }}"
        type_name: "Snort Open Source IDS"
        state: present
        description: "Snort rsyslog source"
        identifier: "{{ hostvars['snort']['private_ip']|regex_replace('\\.','-')|regex_replace('^(.*)$', 'ip-\\1') }}"

- name: Configure Check Point to send logs to QRadar
  hosts: checkpoint

  tasks:
    - include_role:
        name: ansible_security.log_manager
        tasks_from: forward_logs_to_syslog
      vars:
        syslog_server: "{{ hostvars['qradar']['private_ip'] }}"
        checkpoint_server_name: "YOURSERVERNAME"
        firewall_provider: checkpoint

- name: Add Check Point log source to QRadar
  hosts: qradar
  collections:
    - ibm.qradar

  tasks:
    - name: Add Check Point remote logging to QRadar
      qradar_log_source_management:
        name: "Check Point source - {{ hostvars['checkpoint']['private_ip'] }}"
        type_name: "Check Point FireWall-1"
        state: present
        description: "Check Point log source"
        identifier: "{{ hostvars['checkpoint']['private_ip'] }}"

    - name: deploy the new log sources
      qradar_deploy:
        type: INCREMENTAL
      failed_when: false
```
<!-- {% endraw %} -->

> **Note**
>
> Remember to replace the value `YOURSERVERNAME` with your actual server name as mentioned further above.

## Step 1.4 - Run playbooks to enable log forwarding

Run the full playbook to add both log sources to QRadar:

```bash
[student<X>@ansible ~]$ ansible-playbook enrich_log_sources.yml
```

In Check Point SmartConsole you might even see a little window pop up in the bottom left corner informing you about the progress. If that gets stuck at 10% you can usually safely ignore it, the log exporter works anyway.

## Step 1.5 - Verify the log source configuration

Before that Ansible playbook was invoked, QRadar wasn’t receiving any data from Snort or Check Point. Immediately after, without any further intervention by us as security analyst, Check Point logs start to appear in the QRadar log overview.

Log onto the QRadar web UI. Click on **Log Activity**. As you will see, there are a lot of logs coming in all the time:

![QRadar Log Activity showing logs from Snort and Check Point](images/qradar_log_activity.png)

Many of those logs are in fact internal QRadar logs. To get a better overview, click on the drop down menu next to **Display** in the middle above the log list. Change the entry to **Raw Events**. Next, in the menu bar above that, click onto the button with the green funnel symbol and the text **Add Filter**. As **Parameter**, pick **Log Source [Indexed]**, as **Operator**, pick **Equals any of**. Then, from the list of log sources, pick **Check Point source** and click onto the small plus button on the right. Do the same for **Snort rsyslog source**, and press the button **Add Filter**:

![QRadar Log Activity showing logs from Snort and Check Point](images/qradar_filter_logs.png)

Now the list of logs is better to analyze. Verify that events are making it to QRadar from Check Point. Sometimes QRadar needs a few seconds to fully apply the new log sources. Until the new log sources are fully configured, incoming logs will have a "default" log source for unknown logs, called **SIM GENERIC LOG DSM-7**. If you see logs from this default log source, wait a minute or two. After that waiting time, the new log source configuration is properly applied and QRadar will attribute the logs to the right log source, here Check Point.

Also, if you change the **View** from **Real Time** to for example **Last 5 Minutes** you can even click on individual events to see more details of the data the firewall sends you.

Let's verify that QRadar also properly shows the log source. In the QRadar UI, click on the "hamburger button" (three horizontal bars) in the left upper corner, and click on **Admin** down at the bottom. In there, click on **Log Sources**. A new window opens and shows the new log sources.

![QRadar Log Sources](images/qradar_log_sources.png)

Note that so far no logs are sent from Snort to QRadar: Snort does not know yet that this traffic is noteworthy!

But as a security analyst, with more data at our disposal, we finally have a better idea of what could be the cause of the anomaly in the application behaviour. We see the logs from the firewall, see who is sending the traffic, but still not enough data to dismiss the event as a false positive.

## Step 1.6 - Add Snort signature

To decide if this anomaly is a false positive, a security analyst needs to exclude any potential attack. Given the data at your disposal you decide to implement a new signature on the IDS to get alert logs if such traffic is detected again.

In the previous Snort exercise we already added a Snort rule with a signature to get more information, so we can reuse the playbook and only change the rule data. In your VS Code online editor, create a file called `enrich_snort_rule.yml` in your users' home directory with the following content:

<!-- {% raw %} -->
```yaml
---
- name: Add Snort rule
  hosts: snort
  become: yes

  vars:
    ids_provider: snort
    protocol: tcp
    source_port: any
    source_ip: any
    dest_port: any
    dest_ip: any

  tasks:
    - name: Add snort web attack rule
      include_role:
        name: "ansible_security.ids_rule"
      vars:
        ids_rule: 'alert {{protocol}} {{source_ip}} {{source_port}} -> {{dest_ip}} {{dest_port}}  (msg:"Attempted Web Attack"; uricontent:"/web_attack_simulation"; classtype:web-application-attack; sid:99000020; priority:1; rev:1;)'
        ids_rules_file: '/etc/snort/rules/local.rules'
        ids_rule_state: present
```
<!-- {% endraw %} -->

In this play we provide some variables for Snort stating that we want to control any traffic on tcp. Afterwards, with the help of the `ids_rule` role we set a new rule containing the `web_attack_simulation` string as content, making it possible to identify future occurences of this behaviour.

Now execute the playbook:

```bash
[student<X>@ansible ~]$ ansible-playbook enrich_snort_rule.yml
```

Let's quickly verify that the new rule was indeed added. From the terminal of your VS Code online editor, ssh to the Snort server as `ec2-user` and have a look into the directory of custom rules:

```bash
[student<X>@ansible ~]$ ssh ec2-user@11.22.33.44
Last login: Fri Sep 20 15:09:40 2019 from 54.85.79.232
[ec2-user@snort ~]$ sudo grep web_attack /etc/snort/rules/local.rules
alert tcp any any -> any any  (msg:"Attempted Web Attack"; uricontent:"/web_attack_simulation"; classtype:web-application-attack; sid:99000020; priority:1; rev:1;)
```

## Step 1.7 - Identify and close the Offense

Moments after the playbook has been executed, we can check in QRadar if we see Offenses. And indeed, that is the case. Log into your QRadar UI, click on **Offenses**, and there on the left side on **All Offenses**:

![QRadar Offenses](images/qradar_offenses.png)

With these information at our hand, we can now finally check all offenses of this type, and verify that they are all coming only from one single host, the attacker.

In the Offense view, click on the Offense, then in the menu on top on **Actions**, In the drop-down menu-click on **close**. A window will pop up where you can enter additional information and finally close the offense as a false positive.

## Step 1.8 - Rollback

In the final step, we will rollback all configuration changes to their pre-investigation state, reducing resource consumption and the analysis workload for us and our fellow security analysts. Also we need to stop the attack simulation.

We create a new playbook, `rollback.yml`, based on the `enrich_log_sources.yml`. The major differences are that for QRadar we set the state of the log sources to `absent`, for Snort we set `ids_config_remote_log` to `false`, and for Check Point we initiate the tasks for `unforward_logs_to_syslog`.

The playbook `rollback.yml` should have this content:

<!-- {% raw %} -->
```yaml
---
- name: Disable external logging in Snort
  hosts: snort
  become: true
  vars:
    ids_provider: "snort"
    ids_config_provider: "snort"
    ids_config_remote_log: false
    ids_config_remote_log_destination: "{{ hostvars['qradar']['private_ip'] }}"
    ids_config_remote_log_procotol: udp
    ids_install_normalize_logs: false

  tasks:
    - name: import ids_config role
      include_role:
        name: "ansible_security.ids_config"

- name: Remove Snort log source from QRadar
  hosts: qradar
  collections:
    - ibm.qradar

  tasks:
    - name: Remove snort remote logging from QRadar
      qradar_log_source_management:
        name: "Snort rsyslog source - {{ hostvars['snort']['private_ip'] }}"
        type_name: "Snort Open Source IDS"
        state: absent
        description: "Snort rsyslog source"
        identifier: "{{ hostvars['snort']['private_ip']|regex_replace('\\.','-')|regex_replace('^(.*)$', 'ip-\\1') }}"

- name: Configure Check Point to not send logs to QRadar
  hosts: checkpoint

  tasks:
    - include_role:
        name: ansible_security.log_manager
        tasks_from: unforward_logs_to_syslog
      vars:
        syslog_server: "{{ hostvars['qradar']['private_ip'] }}"
        checkpoint_server_name: "YOURSERVERNAME"
        firewall_provider: checkpoint

- name: Remove Check Point log source from QRadar
  hosts: qradar
  collections:
    - ibm.qradar

  tasks:
    - name: Remove Check Point remote logging from QRadar
      qradar_log_source_management:
        name: "Check Point source - {{ hostvars['checkpoint']['private_ip'] }}"
        type_name: "Check Point NGFW"
        state: absent
        description: "Check Point log source"
        identifier: "{{ hostvars['checkpoint']['private_ip'] }}"

    - name: deploy the log source changes
      qradar_deploy:
        type: INCREMENTAL
      failed_when: false
```
<!-- {% endraw %} -->

> **Note**
>
> Again, remember to replace the value of `YOURSERVERNAME` with the actual server name of your Check Point instance.

While this playbook is maybe the longest you see in these entire exercises, the structure and content should already be familiar to you. Take a second to go through each task to understand what is happening.

Run the playbook to remove the log sources:

```bash
[student<X>@ansible ~]$ ansible-playbook rollback.yml
```

Also, we need to kill the process which simulates the attack. For this we will use a so called Ansible ad-hoc command: a single task executed via Ansible, without the need to write an entire playbook. We will use the shell module because it supports piping, and can thus chain multiple commands together. In a terminal of your VS Code online editor, run the following command:

<!-- {% raw %} -->
```bash
[student1@ansible ~]$ ansible attacker -b -m shell -a "sleep 2;ps -ef | grep -v grep | grep -w /usr/bin/watch | awk '{print $2}'|xargs kill &>/dev/null; sleep 2"
attacker | CHANGED | rc=0 >>
```
<!-- {% endraw %} -->

The ansible command connects to the **attacker** machine with escalated privileges (`-b`) and runs the shell module there (`-m shell`). The parameter of the shell module is a chain of shell commans. We output all running processes, remove lines where grep is part of the command itself, assuming that those are not of value to us. We then filter for all commands executing watch, use awk to get the process ID and hand the process ID over to `kill`.

If you get an error saying `Share connection to ... closed.`, don't worry: just execute the command again.

You are done with the exercise. Turn back to the list of exercises to continue with the next one.

----
**Navigation**
<br>
[Previous Exercise](../1.4-qradar) - [Next Exercise](../2.2-threat)

[Click Here to return to the Ansible Security Automation Workshop](../README.md#section-2---ansible-security-automation-use-cases)
