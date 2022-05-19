```
title: HCMUS-CTF: LostInParis [Forensic]
author: The Archivist
date: 2022-5-19 9:30:00 +1345
```

The task provides only a file called `forensic` and `file` command cannot detect its type

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_07-25.png)

so I have to perform a manual check on it using `xxd` and take the first for bytes into consideration.

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_07-27.png)

As shown in the image, its signature consists of `53 ff 00 f0` which indicates the file itself is a memory snapshot. In order to analyze a memory image, you will need to have [Volatility](https://github.com/volatilityfoundation/volatility) installed and after that, we can delve deeper into the binary.

In the very first stage, let's determine the analysis profile for `forensic`:

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_07-39.png)

Next we want to see what processes were running by issuing `pslist` to Volatility:

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_07-42.png)

`wordpad.exe` was running with PID 3212 and let's dump the process content then search for emails, twitter, etc.

Scroll down a little and we can see its twitter credentials as `w3twit:OverIsMyHero`

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_07-51.png)

Since we only need the password so it'd be `OverIsMyHero`.

That brings us to the end of the first part, in the following stage, we will take a look into where Windows stores its password (herein `hivelist`) and search for the virtual offset of SYSTEM and SAM thereby extracting the hashes.

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_07-58.png)

Let's dump the two and crack them.

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_12-55.png)

Using either `hashcat` or `john` should give you the right password - `IL0VEFORENSIC`. Please notice that we only need to crack `w3user` as the Twitter handle was `w3twit`, therefore, the last password should be of something `w3???@somemail.com`.

 ![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-12.png)

So the email was `w3user@incredimail.com` and yet, their website has closed since long ago.

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-19.png)

After a few search on Google about how to recover Incredimail's passwords, I came across this one:

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-18.png)

Evidently, the passwords were stored offline in the registry at `HKEY_CURRENT_USER\Software\Incredimail\Identities\`, so let's take a look there.

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-22.png)

Keep diving in and we does find the account field:

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-23.png)

And we will dump the whole registry then search for in which the Incredimail's credentials is lying.

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-34.png)

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-42.png)

So these registry images have our passwords, we will rebuild the registry then use a tool called Incredimail Password Recovery to recover the passwords therein.

Let's fire up a Windows virtual machine and import the registry data.

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-46.png)

And here it is:

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-47.png)

We finally get the last password as `SnapshotIsReallyNiceForHacker`

![](https://raw.githubusercontent.com/legiahuyy/external-post/main/images/2022-05-19_13-58.png)

Combine all parts we have the flag:

```
HCMUS-CTF{IL0VEFORENSIC_SnapshotIsReallyNiceForHacker_OverIsMyHero}
```