
| Section           | Question Number | Answer                       |
| ----------------- | --------------- | ---------------------------- |
| Skills Assessment | Question 1      | Naive Bayes                  |
| Skills Assessment | Question 2      | Principal Component Analysis |
| Skills Assessment | Question 3      | Q-Learning                   |
| Skills Assessment | Question 4      | Neuron                       |
| Skills Assessment | Question 5      | Transformers                 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Skills Assessment

## Question 1

### "Which probabilistic algorithm, based on Bayes' theorem, is commonly used for classification tasks such as spam filtering and sentiment analysis, and is known for its simplicity, efficiency, and good performance in real-world scenarios?"

`Naive Bayes` is a probabilistic algorithm used for `classification` tasks. It's based on `Bayes' theorem`, a fundamental concept in probability theory that describes the probability of an event based on prior knowledge and observed evidence. `Naive Bayes` is a popular choice for tasks like spam filtering and sentiment analysis due to its simplicity, efficiency, and surprisingly good performance in many real-world scenarios.

![[HTB Solutions/Others/z. images/16ca270a6850cfcf4e763a9d4c403845_MD5.jpg]]

Answer: `Naive Bayes`

# Skills Assessment

## Question 2

### "What dimensionality reduction technique transforms high-dimensional data into a lower-dimensional representation while preserving as much original information as possible, and is widely used for feature extraction, data visualization, and noise reduction?"

`Principal Component Analysis` (PCA) is a dimensionality reduction technique that transforms high-dimensional data into a lower-dimensional representation while preserving as much original information as possible. It achieves this by identifying the principal components and new variables that are linear combinations of the original features and capturing the maximum variance in the data. PCA is widely used for feature extraction, data visualization, and noise reduction.

![[HTB Solutions/Others/z. images/64647e2fd3698dc739293dc23efd4bd6_MD5.jpg]]

Answer: `Principal Component Analysis`

# Skills Assessment

## Question 3

### "What model-free reinforcement learning algorithm learns an optimal policy by estimating the Q-value, which represents the expected cumulative reward an agent can obtain by taking a specific action in a given state and following the optimal policy afterward? This algorithm learns directly through trial and error, interacting with the environment and observing the outcomes."

`Q-learning` is a model-free `reinforcement learning` algorithm that learns an optimal policy by estimating the `Q-value`. The `Q-value` represents the expected cumulative reward an agent can obtain by taking a specific action in a given state and following the optimal policy afterward. It's called "model-free" because the agent doesn't need a prior model of the environment to learn; it learns directly through trial and error, interacting with the environment and observing the outcomes.

![[HTB Solutions/Others/z. images/b0f39fc0f4a9edf9c232a727949b226b_MD5.jpg]]

Answer: `Q-learning`

# Skills Assessment

## Question 4

### "What is the fundamental computational unit in neural networks that receives inputs, processes them using weights and a bias, and applies an activation function to produce an output? Unlike the perceptron, which uses a step function for binary classification, this unit can use various activation functions such as the sigmoid, ReLU, and tanh."

A `neuron` is a fundamental computational unit in neural networks. It receives inputs, processes them using weights and a bias, and applies an activation function to produce an output. Unlike the perceptron, which uses a step function for binary classification, neurons can use various activation functions such as the `sigmoid`, `ReLU`, and `tanh`.

![[HTB Solutions/Others/z. images/0e28bcae22fb81ca5c0d1c201daf5884_MD5.jpg]]

Answer: `neuron`

# Skills Assessment

## Question 5

### "What deep learning architecture, known for its ability to process sequential data like text by capturing long-range dependencies between words through self-attention, forms the basis of large language models (LLMs) that can perform tasks such as translation, summarization, question answering, and creative writing?"

These models are trained on massive amounts of text data, allowing them to learn patterns and relationships in language. This knowledge enables them to perform various tasks, including translation, summarization, question answering, and creative writing.

LLMs are typically based on a `deep learning` architecture called `transformers`.

![[HTB Solutions/Others/z. images/3a0a2636e0649d40ed50837273aaf990_MD5.jpg]]

Answer: `transformers`