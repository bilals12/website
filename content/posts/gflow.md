---
title: "perceptrons to GFlowNets"
date: 2024-03-25T12:39:06-04:00
draft: true
math: true
---

# baking 101

there's a famous quote by carl sagan, from the book/series "cosmos" that goes:

`to bake a pie from scratch, you must first create the universe.`

cute, isn't it? it can apply to loads of different fields and disciplines and products of human ingenuity, and the idea behind it is simple enough for anyone to grasp: the creation of anything goes back far beyond the individual ingredients required to create the thing itself. 

[carl sagan image]

"saltation", in biology, is a "sudden and large mutational change from one generation to the next, potentially causing single-step speciation". think of it like a y-curve, except it's not continuous but has a large discontinuous "jump" or "jumps" inside it. it helps to know that saltation comes from the latin for *saltus*, which translates literally to "leap" or "jump". 

"saltation" is also a term used in geology, where the meaning is slightly different (but still based on the latin root). in geology, saltation occurs when a type or particle is transported by fluids, like pebbles being transported by rivers or sands by wind. material can be transported either by saltation, or reptation (also known as "creep", where the material stays in contact with the surface).

it may help to rely on these analogies when thinking of seemingly sudden or abrupt advances in computational technology. it might be even more helpful, however, to think of advances in computational technology as the result of very focused and iterative progress. decades of chasing marginal improvements in performance and efficiency can lead to an almost startling explosion of knowledge and results and,  before you get your head around the subject, another development is already overshadowing the previous one. 

# history lessons

the concept of AI has been around for virtually over a century. since "thinking machines" came into public consciousness and were made real through the work of countless engineers and scientists, there has been a steady march towards the goal of having machines "think" and "reason". while i won't get into the philosophical ramifications of what it means to have a machine "think", it's worth mentioning that immense progress has been made in getting computers to process massive swarms of data and give us their takeaways from said data. sometimes it feels like it all came out of nowhere, but artificial intelligence (which, as of now, really just means neural networks and deep learning) has been in the making for a long time. the latest in this chain of evolution that caught my interest is a new type of learning model: GFlowNets.

## learning models

the concept of "neural networks" goes all the way back to the early 1940s. warren mcculloch (a neuroscientist) and warren pits (a logician) proposed a computational model of a neuron, based on the structure of a biological neuron. a biological neuron can be thought of as a connection of 4 components: dendrites, soma, axon, and synapse. the dendrite receives signals from other neurons (input). the soma processes the information and transmits it via the axon (output) to the synapse, where it's connected to other neurons.

### perceptrons + early neural networks (1950s)

the mcculloch-pitts neuron (MCP or "perceptron"), consists of 2 parts: g(x) and f(g(x)). in simpler terms, $g(x)$ takes inputs ($x_1$ to $x_n$) and $f(g(x))$ makes a simple boolean decision (1 or 0). the values of $g(x)$ were bound by a variable called "theta" ($\theta$), which can also be thought of as the "thresholding parameter". 

the MCP was a restricted kind of artificial neuron, and it operated in discrete time-steps (t = 0, 1, 2, 3...). this model of the neuron led to the invention of an algorithm called the perceptron. frank rosenblatt was inspired by the goal of mimicking the human brain's functionality, and thus designed the perceptron as a model for biological neurons, capable of performing simple binary classification tasks (i.e. deciding whether or not an input, represented by a vector of numbers, belongs to some specific class).

the simplest form of a neural network was therefore created and modeled by a simple equation: $f(x) = sign(wx + b)$. this was a straightforward and intuitive way of showing how a combination of weights (represented by $w$, the weights vector) and inputs (represented by $x$, the input vector) can be used to make binary decisions. $sign()$ outputs 1 for positive values and -1 or 0 for negative values. 

some of my readers might notice a little problem in this model: it can only represent linearly separable functions. to put it another way, the perceptron uses a linear function to decide whether an input belongs to one class or another. it computes a weighted sum of the inputs, adds a bias, and applies a threshold (step function) to the sum to decide the output class: $f(x) = 1$ if $wx + b > 0$, else $f(x) = 0$. 

the perceptron was foiled by a problem known as "the XOR problem". XOR is a binary function that outputs "true" (1) if exactly one of its inputs are true. if both inputs are true (or false), it outputs "false" (0). it foils the perceptron because no straight line can be drawn to divide the inputs that result in 1 from those that result in 0. the pursuit of the solution to this problem led everyone to the development of multi-layer neural networks (aka MLPs: multi-layer perceptrons). 

### detour: weights + biases

understanding the concepts of weights and biases is central to understanding the mathematics of neural networks. weights ($w$) are parameters that determine the strength of the input signal as it propagates through the network. when given an input vector $x = [x_1, x_2, ..., x_n]$, the weighted sum of the inputs is calculated as $wx = w_1x_1 + w_2x_2 + ... + w_nx_n$ (where $w = [w_1, w_2, ..., w_n]$ is the weight vector). this sum is crucial in understanding and developing the neuron's *activation function* (more on that later), because it determine's the neuron's output based on the input received. 

the neural network "learns" by adjusting the weights based on the error between the predicted output and the actual output. this process is called *backpropagation*, where the gradient of the loss function with respect to each weight is calculated and the weights are updated to minimize the loss. once the neural network "learns" the appropriate values of these weights, it can then "learn" to recognize specific features in images, semantic content in text, and even predict future values in time-series data.

the bias $b$, on the other hand, is a parameter that allows the activation function to be shifted to the left or right, to "fit" the data. think of it like the intercept in a linear regression model, or even more simply as the $y$-intercept in that famous equation of a line we all learned in school: $y = mx + b$.

the bias is added to the weighted sum of the inputs before being passed through the neuron's activation function. it enables the neuron to "activate" (i.e. produce a non-zero output) even when all inputs are zero, thus allowing the model to fit the data more flexibly. like weights, biases are learned by iteratively adjusting their values to minimize the loss function during training. without bias, a neuron's output would be constrained to always pass through the origin ($0,0$) in the I/O space, limiting the model's flexibility and expresiveness. long story short, the neural network needs to better fit a wide variety of patterns in the data so it can have improved predictive performance. 

### 


Here is a display equation:
$$ x = \frac{-b \pm \sqrt{b^2-4ac}}{2a} \$$

Here is an inline equation: $(E = mc^2\)$.

This is an inline $a^*=x-b^*$ equation.

An equation:
 $$\int_{-\infty}^{\infty} e^{-x^2} dx$$.  <!-- works -->
 
 inline example: $\sum_{i = 0}^N 2i = y$ <!-- works -->
 
 One overbrace:
 
 $${a}^{b} - \overbrace{c}^{d}$$  <!-- works-->
 
 Two overbraces:
 $$\underbrace{a}_{b} - \underbrace{c}_{d}$$  <!--does not work -->
 
 
 None of these below works properly:
 
 $$
 \begin{aligned}
         equation &= 16 \\
         other &= 26 + 13
 \end{aligned}
 $$
 
 $$
 \begin{pmatrix}
    a & b \\
       c & d
       \end{pmatrix}
 $$

$x = {-b \pm \sqrt{b^2-4ac} \over 2a}$