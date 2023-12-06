---
title: "ddos flood part I"
date: 2023-12-06
draft: false
---

![banned](/12344.png)


earlier this week, while trawling through forums looking for malware and worm samples, i was surprised to find a rather intriguing, but hideous, slab of code. the source was a private channel for hackers of presumably israeli origin, and the script itself was part of a fully functional DDoS suite, including a .exe file for windows systems as well as a .apk for android smartphones. running the script from a *nix system seems simple enough:

```bash
./script.js --workers 120
```

the original script was immensely difficult to read, as it had been minified and spaghetti-fied, but i was able to un-minify it for deeper analysis. they're both up on my [github](https://github.com/bilals12/ddosResearch), but can only be viewed in raw format, as the code itself exceeds 50,000 lines. just for shits and giggles, i've posted it in its entirety at the very bottom of this post (edit: i've since had to remove the snippet because it kept crashing my site!). this post will analyze the first significant chunk of the code (up to line 3000 or so), that deals with the DDoS attack class definition.

# flow

though complex, the script has a somewhat intuitive flow if you know how a DDoS works. 

1. importing dependencies
2. setting up the DDoS attack
3. starting the DDoS attack
4. firestore document creation
5. error handling
6. utility functions
7. utility exports

# importing dependencies

the script starts by importing various dependencies. dependencies are libraries or modules which provide additional functionality to the script. 

## axios library

axios is a popular HTTP client for JavaScript, used to make HTTP requests from node.js or `XMLHttpRequests` from inside the browser. inside this script, however, a bundled version of axios is included. it's used extensively throughout the script to make HTTP requests, and is configured with default settings but also includes the functionality for intercepting requests and responses, which are used for things like adding headers, transforming data, or handling errors globally.

1. module definition (ln 1 - 5):
- the script starts with a module definition. this is to ensure compatibility with different module systems.

2. axios core:
- this includes the definition of the main `Axios` class, which is used to make HTTP requests.
- the class includes methods for each type of HTTP request (`get`, `post`, `delete`, `put`), as well as a generic `request` method.

3. interceptors:
- axios allows you to intercept requests or responses before they are handled by `then` or `catch`.
- interceptors are useful for adding headers, logging, or handling errors globally.
- in this script, the `Axios` class includes a `request` and `response` interceptor.

4. configuration defaults:
- axios allows for custom configuration of requests.
- this includes the base URL, headers, params, timeout, and more.
- in this script, the `Axios` class merges the instance's default config with the request config.

5. promise handling:
- promises in JavaScript are objects that represent the eventual completion or failure of an asynchronous operation and its resulting value.
- in this script, the `Axios` class methods return promises that resolve to the response of the HTTP request.

6. error handling:
- if a request or response interceptor throws an error, it is caught and the promise is rejected with the thrown error.

## utility functions

the script imports a large number of utility functions and classes, for different purposes.

1. handling promises (`wc`).
2. working with URLs (`$c, zc, Yc, Jc, Zc, tc, nc, oc, rc, sc, cc, pc, lc, hc, yc, uc, dc, wc, bc, mc, gc, vc, Ec, Tc, Nc, Cc, Ac, Sc, Ic, Oc, Qc, Jc, Zc, t5, n5, o5, r5, s5, c5, p5, l5, h5, y5, u5, d5, w5, b5, m5, g5, v5, E5, T5, N5, C5, A5, S5, I5, O5, Q5, J5, Z5, e4, t4, V2, i4, Q2, Z2, t8, o8, c4`).
3. handling HTTP requests (`Wg, Xg, zg, eg, tg, ng, og, rg, sg, cg, pg, lg, hg, yg, ug, dg, wg, bg, mg, gg, vg, Eg, Tg, Ng, Cg, Ag, Sg, Ig, Og, Qg, Jg, Zg, e8, t8, n8, o8, r8, s8, c8, p8, l8, h8, y8, u8, d8, w8, b8, m8, g8, v8, E8, T8, N8, C8, A8, S8, I8, O8, Q8, J8, Z8, e4, t4, n4, o4, r4, s4, c4, p4, l4, h4, y4, u4, d4, w4, b4, m4, g4, v4, E4, T4, N4, C4, A4, S4, I4, O4, Q4, J4, Z4, e2, t2, n2, o2, r2, s2, c2, p2, l2, h2, y2, u2, d2, w2, b2, m2, g2, v2, E2, T2, N2, C2, A2, S2, I2, O2, Q2, J2, Z2, e0, t0, n0, o0, r0, s0, c0, p0, l0, h0, y0, u0, d0, w0, b0, m0, g0, v0, E0, T0, N0, C0, A0`).

# setting up the DDoS attack + start

## DDoS attack class

1. definition
- the `Wg` class is defined with several properties. this is the main class for executing the DDoS attack. 
- the properties include `workers`, `planer`, `maxWorkers`, `logTimestamp`, and `logRequests` and are used to configure the behaviour of the DDoS attack.

2. constructor
- the constructor of the `Wg` class is used to initialize an instance of the class (`$r`). this instance `$r` is an object that encapsulates the state and behaviour of the DDoS attack.
- it sets the `executorStrategy` to either the provided `planer` or `automatic` if none is provided.
- it also sets the `useRealIP` property based on the `withProxy` property.
 it includes methods for starting the attack (`start`), adjusting the number of executors (`adjustWorkers`), and handling responses (`handleResponse`). the class also includes properties for the target URL, number of workers, and execution strategy.

 3. `start` method
 - used to start the attack.
 - first checks if the `executionStrategy` type is set to "automatic".
 - if it is, it sets the `maxExecutorsCount` to either the provided `maxWorkers` or `128` if none is provided.
 - it then sets the `executorsCount` to the number of `workers`.
 - finally, it sets up the `logTimestamp` and `logRequests` properties based on the provided values, or defaults to `true` if none are provided.

 4. `AdjustWorkers` method
 - used to adjust the number of workers (concurrent requests) during the attack.
 - it takes a number as an argument and adjusts the `workers` property of the `Wg` instance accordingly.
 - this allows the script to dynamically adjust the intensity of the DDoS attack.
 - the parameter is aliased as `g9`

 5. `HandleResponse` method
 - used to handle the responses from the target server.
 - it takes a response as an argument and processes it.
 - this involves logging the response, checking for errors, or other actions based on the response.

 ## setup
 
 once the `Wg` class is defined, an instance of the class is created using the `new` keyword. the constructor then takes several parameters to configure the attack.

 ```js
 let attackInstance = new Wg(targetURL, workers, withProxy);
 ```

 ## start

 after the instance is created and configured, the `start` method is called on the instance to start the attack. this method sets up the attack based on the properties of the instance and then starts making requests to the target server.
 ```js
 attackInstance.start()
 ```

the exact details of how the `start` method works depend on the implementation in the `Wg` class, and will be covered in a future post.


# firestore document creation

the `KG` function is defined. this creates a new document in firestore with the current date as `startDate`. this is used to keep track of when the DDoS attack was started. firestore is a NoSQL document database that's build for automatic scaling and high performance. my feeling is that the document would include information such as the target, the number of workers, and other configuration details. this could be used for monitoring the attack, analyzing its effectiveness, or just for record-keeping.

# error handling

a global error handler is set up, which logs any uncaught exceptions to the console. this is a very common practice in Node.js to prevent the app from crashing when an unhandled error occurs, and is critical for maintaining the stability of the script during the execution of the DDoS attack. errors related to network issues, server responses, or internal script errors can be logged and then resolved.

# utility exports

building off of the aforementioned utility functions, the script exports them and uses them in other parts of the project. these will be covered in a later post.

