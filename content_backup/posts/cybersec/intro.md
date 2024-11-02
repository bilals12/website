---
title: "intro to hacking"
date: 2021-10-24T01:43:33-05:00
draft: false
toc: false
images:
tags: ["cybersec"]
---

over the past year, i felt something i haven't felt in a long time. passion, for a new hobby and possibly a new field of work: cybersecurity. more specifically, pen(etration)testing.

the story is pretty boring. as a kid, i was fascinated by computers. then, like so many young wannabe hackers, i watched "the matrix" and i became even more fascinated. not so much by computers, but rather how to get into computers and networks i'm not supposed to.


### before


i grew up in the uae. the emirate of sharjah, to be precise. my mother was a professor in the university, and as such we had to live in the faculty housing on campus. the campus was connected as an intranet (a really big private network), so the already restricted internet access of the uae was restricted even further. this meant that i had no access to torrenting applications, online gaming, and, of course, other...*sites* that i wanted to visit very much but was simply not allowed to. friends of mine, who weren't in the intranet, had access to torrenting apps and online gaming, so it was just another thing i seemed to be left out of. for a long time, we hung out in internet/gaming cafes, gaming for hours and downloading whatever we wanted. my biggest weaknesses at the time, and even now, were music and movies. streaming didn't exist at the time so my options were either a) get it all at a cafe, using blazingly-fast (at the time) DSL or b) have a friend burn me CDs/DVDs with all the stuff i wanted. far from ideal. 

over time, a proxy server and early vpn known as hotspotshield became popular for, y'know, *stuff*, and everyone seemed to be using it. i tried to use it to torrent but in our intranet, it was either throttled to be unusable and eventually blacklisted. so what did i end up doing? why, learning linux of course!


someday, i'll have to find and thank the person who got me interested in such things. he was, and probably still is, a massive geek with an almost unbelievable memory and penchant for all things computer-related. he taught me how to use linux (ubuntu) and connect via ssh to a host he'd set up somewhere (don't know how) outside the country. this was my first experience with virtualization, ssh, and properly configured vpns that would maintain my anonymity (i thought) and provide a usable connection speed that could also be used for gaming and torrenting. i was elated. suddenly, i had broken out of the restrictions that i had halfway accepted and the entire internet was at my fingertips. emphasis on **entire**.


eventually, the remote host died for good and i lost access to the proxy. bummer. by that point, i had figured out (with the help of another student at my school who also happened to be my neighbour), how to enumerate and access smb shares on the intranet. as you may know, university campuses almost always had some version of a massive file sharing app like dc++ running, where students could freely share movies and music. dc++ didn't exactly work for us, maybe because we weren't connected to the student network, but somehow we could view some public smb shares where some students had set up their shared folders. once we had that, it was almost better than torrenting. of course, the music was never up to my standards but there was always a metalhead somewhere in the mix from whom i'd copy (steal) music. 


i ended up leaving the country to study in canada and my access widened, so my early foray into hacking went limp and then died. i majored in electrical engineering, so the hacking was mostly physical. i learned a lot about assembly and memory, on a physical but still somewhat abstract level. learning electronics was also fun, but i didn't really care for it. however, i finished my degree and ended up getting a job as a software and database developer.

coding was never something i was super into, beyond an aesthetic appreciation. it was kinda cool, and that was about it. it was also the career of choice for many engineers who couldn't stand their original discipline and just wanted a job. i was one of them, and here i was.



### now


when the pandemic hit, i felt boredom on a metaphysical level. i'm the kind of person who already gets easily bored, so being made to stay at home and do something i only halfway enjoyed was not it. i wanted to do something different, something exciting. but what? 

it just so happened that my interest in infosec/cybersec never truly died, that i happened to follow many infosec professionals and pentesters on twitter. i hardly ever knew what they were talking about, but i liked it. in the past year, it hit me. if i like it so much, what's stopping me from actually doing it? not much, in fact. and so i started looking more closely. and learning.


i quickly identified pentesting as my dream field. i started to consume vast amounts of information on the field: what they do, their certifications, their techniques. i joined online communities like tryhackme, and even signed up for a junior pentesting cert from elearnsecurity. now, i have both the eJPT cert as well as a bunch of completed rooms on tryhackme to my name. it may not be much, but i was hooked. 


in the past year, i've learned more and more about linux, windows, networking, databases (beyond the scope of my job), shell scripting, web hacking, enumeration, footprinting, scanning, vulnerabilities. i've learned and practiced a variety of attacks: bruteforce/dictionary attacks using hydra, xss, sql injections, arp poisoning, file inclusions, remote code executions (reverse shells), privilege escalation, and finally, active directory. what's missing here? the other side! and so i started to learn about defense: firewalls, SIEMs, IPS/IDS, hardening...and there's still so much to learn.



### then


i learned that when you truly enjoy something, you don't get tired of it. rather, you can't get tired of it. i want to keep going, and keep learning, and keep getting better. i hope to get a job in the field where i can learn from true professionals and real systems. i'm also going to use this site to dump whatever i've learned, whatever room i've solved, and pretty much anything else i feel like.

to whoever's reading this: thank you. and i hope that whatever you find yourself naturally gravitating towards, you accept it and lean into it and turn it into a passion. 




