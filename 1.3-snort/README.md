# Exercise 1.3 - Executing the first Snort playbook

## Step 3.1 - Snort

To showcase how to automate a network intrusion detection and intrusion prevention system in a security environment, this lab will take you through managing a Snort IDS instance. Snort analyzes network traffic and compares it against some given rule set.
In this lab, Snort is installed on a Red Hat Enterprise Linux machine and Ansible interacts with it by accessing the RHEL node over SSH.


## Step 3.2 - Simple Snort rules

In the most basic capacity, Snort works by reading some rules and acting according to them. In this lab, we will be working with some simple examples of Snort in order to show how to automate this configuration with Ansible. This session is not designed to dive into the specifics of Snort rules and the complexity involved in large setups, however, it is helpful to understand the basic structure of a simple rule so that you are aware of what you are automating.

A rule consists of a rule header and rule options and is saved in files.

The Snort rule header breaks down into:

- an action
- the protocol to look for like TCP
- source information like IP and port
- destination information like IP and port

The Snort rule options are keywords separated by `;` and can be:

- messages to output when a rule matches
- SID, a unique identifier of the rule
- content to search for in the packet payload, for example a suspicious string
- or byte tests to check for binary data
- a revision of the rule
- the severity of the attack, called "priority"
- a pre-defined attack type called "classtype" to better group the rule with other rules
- and others.

Not all options are mandatory, some also only override existing default values.

A Snort rule's outline is as follows:

```
[action][protocol][sourceIP][sourceport] -> [destIP][destport] ( [Rule options] )
```


## Step 3.3 - Example playbook

As discussed earlier, Ansible automation is described in playbooks. Playbooks consist of tasks. Each task uses a module and the module's corresponding parameters to describe the change that needs to be done or the state that is desired.

The Snort modules used in these examples are shipped as part of a "role". To better describe a role, think about how you wrote your playbook in the last section. While it is possible to write a playbook in one file as we did earlier, often writing all automation pieces in one place results in creating long, complicated playbooks. At some point you will want to reuse the automation content you wrote in your playbooks already. Therefore, you will need to organize things in a way to get multiple smaller playbooks to work together. Ansible Roles are the way we achieve this. When you create a role, you deconstruct your playbook into parts and those parts sit in a directory structure.

Let's have a look at how this playbook can be re-written to use the roles directly. To do this, we first need to download and install the role on our control host. There are several ways to do this but a very convenient way is the command line tool `ansible-galaxy`. This tool installs roles directly from the archives, Git URLs and from [Ansible Galaxy](https://galaxy.ansible.com). Ansible Galaxy is a community hub for finding and sharing Ansible content. The role mentioned above can be found in Ansible Galaxy at [ansible_security/ids_rule](https://galaxy.ansible.com/ansible_security/ids_rule).

On the command line, you can use the `ansible-galaxy` tool to download and install the `ids_rule` role with a single command. Execute the following command in a terminal of your VS Code online editor:

```bash
[student<X>@ansible ~]$ ansible-galaxy install ansible_security.ids_rule
- downloading role 'ids_rule', owned by ansible_security
- downloading role from https://github.com/ansible-security/ids_rule/archive/master.tar.gz
- extracting ansible_security.ids_rule to /home/student<X>/.ansible/roles/ansible_security.ids_rule
- ansible_security.ids_rule (master) was installed successfully
```

As you see the role is installed to the roles default path, `~/.ansible/roles/`.It was prefixed by `ansible_security`, this is the name of the project used for security roles, such as what we are using in this lab.

Now that we have the role installed on our control host, we can use it in a playbook. In order to use the role, create a new file called `add_snort_rule.yml` in your VS Code online editor and save it in the home directory of your user. Since we need root rights to make any changes on Snort, add the `become` flag so that Ansible would take care of privilege escalation.

```yaml
---
- name: Add Snort rule
  hosts: snort
  become: yes
```

Next we need to add the variables required by our playbook. The role we are using is written in a way that can work with multiple IDS providers, all the user needs to provide is the name of the IDS and the role will take care of the rest. Since we are managing a Snort IDS, we need to set the value of `ids_provider` variable to `snort`.

```yaml
---
- name: Add Snort rule
  hosts: snort
  become: yes

  vars:
    ids_provider: snort
```

Next, we need to add the tasks. Since we are using a role, we can simply use a single step in our tasks, `include_role`, to add it to our playbook. In order to make the role suitable for our use case, we add the following task-specific variables:

- the actual rule
- the Snort rules file
- the state of the rule, present or absent

```yaml
---
- name: Add Snort rule
  hosts: snort
  become: yes

  vars:
    ids_provider: snort

  tasks:
    - name: Add snort password attack rule
      include_role:
        name: "ansible_security.ids_rule"
      vars:
        ids_rule: 'alert tcp any any -> any any (msg:"Attempted /etc/passwd Attack"; uricontent:"/etc/passwd"; classtype:attempted-user; sid:99000004; priority:1; rev:1;)'
        ids_rules_file: '/etc/snort/rules/local.rules'
        ids_rule_state: present
```

Let's have a quick look at what is happening here. the rule header is `alert tcp any any -> any any`, so we create an alert for tcp traffic from any source to any destination.
The rule options define the human readable Snort message if and when the rule finds a match. `uricontent` which is a specialized version of `content` making it easier to analyze URIs. The `classtype` is set to `attempted-user` which is the default class for "attempted user privilege gain". SID is set to a value high enough for user defined rules. The priority is `1` and finally since this is the first version of this rule we set the revision to `1`.

The other variables, `ids_rules_file` and  `ids_rule_state` provide the user defined location for the rules file and state that the rule should be created if it does not exist already (`present`).

## Step 3.4 - Run the playbook

It is now time to execute the playbook. Call `ansible-playbook` with the playbook name:

```bash
[student1@ansible ~]$ ansible-playbook add_snort_rule.yml
```

As you can see when you run this playbook, there are many tasks executed in addition to adding the rules. For instance, the role reloads the Snort service after the rule is added. Other tasks ensure that the variables are defined and verified.
This yet again highlights the value of using roles. By taking advantage of roles, you are not only making your content re-usable but you can also add verification tasks and other important steps and keep them neatly hidden inside the role. 

## Additional Information 

If you want to learn more about Snort rules, check out the [Snort Rule Infographic](https://www.snort.org/documents/snort-rule-infographic) or dive into the [Snort Users Manual (PDF)](https://www.snort.org/documents/snort-users-manual). If you want to have a look at some real Snort rules you can also access the Snort installation in your lab and look at the content of the `/etc/snort/rules` directory.


----
**Navigation**
<br>
[Previous Exercise](../1.2-checkpoint) - [Next Exercise](../1.4-qradar)

[Click Here to return to the Ansible Security Automation Workshop](../README.md#section-1---introduction-to-ansible-security-automation-basics)
