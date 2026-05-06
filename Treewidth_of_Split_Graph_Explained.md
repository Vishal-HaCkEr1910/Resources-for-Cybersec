# 🌳 Treewidth of Split Graph — Explained for Beginners

> **Note:** This document explains your TOC assignment on computing the treewidth of split graphs in a simple, beginner-friendly way — with analogies, step-by-step breakdowns, and plain English.

---

## 📌 Table of Contents

1. [What is a Graph? (The Very Basics)](#1-what-is-a-graph-the-very-basics)
2. [What is a Clique?](#2-what-is-a-clique)
3. [What is an Independent Set?](#3-what-is-an-independent-set)
4. [What is a Split Graph?](#4-what-is-a-split-graph)
5. [What is Treewidth? (And Why Does it Matter?)](#5-what-is-treewidth-and-why-does-it-matter)
6. [The Hammer-Simeone Formula (Theorem 3.1)](#6-the-hammer-simeone-formula-theorem-31)
7. [Algorithm 1 — Detecting a Split Graph](#7-algorithm-1--detecting-a-split-graph)
8. [Algorithm 2 — Computing the Treewidth](#8-algorithm-2--computing-the-treewidth)
9. [Worked Example 1 — Step by Step](#9-worked-example-1--step-by-step)
10. [Worked Example 2 — Step by Step](#10-worked-example-2--step-by-step)
11. [Summary Cheat Sheet](#11-summary-cheat-sheet)

---

## 1. What is a Graph? (The Very Basics)

A **graph** is just a collection of:
- **Vertices (V)** — think of them as people, cities, or objects (represented as dots/circles)
- **Edges (E)** — connections between those vertices (represented as lines)

**Example:** A social network is a graph. Each person is a vertex. A friendship is an edge.

```
A --- B
|     |
C --- D
```
Here, A, B, C, D are vertices. The lines between them are edges.

The **degree** of a vertex is simply how many edges are connected to it.
- In the graph above, A has degree 2 (connected to B and C).

---

## 2. What is a Clique?

A **clique** is a group of vertices where **every single pair is connected** to each other.

Think of it as a group of friends where everyone knows everyone.

**Example:** If A, B, C are a clique:
```
A --- B
 \  /
  C
```
- A–B are connected ✅
- B–C are connected ✅
- A–C are connected ✅

A clique of size `k` has exactly `k*(k-1)/2` edges.

---

## 3. What is an Independent Set?

An **independent set** is the exact opposite of a clique — a group of vertices where **no two vertices are connected** to each other.

Think of it as strangers at a party who don't know anyone else in the group.

**Example:** If D and E form an independent set:
```
D    E
```
- D and E are NOT connected to each other ✅
- They may individually connect to other vertices outside the set.

---

## 4. What is a Split Graph?

A **split graph** is a graph where you can divide ALL its vertices into exactly two groups:
- A **Clique C** — everyone is connected to everyone inside this group
- An **Independent Set I** — nobody is connected to anyone else inside this group

The vertices in I can still connect to vertices in C — they just can't connect to each other.

**Visual Intuition:**
```
    [ Clique C ]      [ Independent Set I ]
    A --- B           D      E
     \  / \           |     /
      C    \----------+----/
```
- A, B, C are all connected to each other (clique)
- D and E are NOT connected to each other (independent set)
- D and E DO connect to some vertices in the clique

---

## 5. What is Treewidth? (And Why Does it Matter?)

**Treewidth** is a number that measures how "tree-like" a graph is.

- A **tree** (graph with no cycles) has treewidth = **1**
- A **complete graph** (everyone connected to everyone) of n vertices has treewidth = **n−1**
- The **lower** the treewidth, the easier many graph problems are to solve

**Why does it matter in TOC (Theory of Computation)?**
Many computational problems that are generally hard (NP-hard) become much easier — even polynomial time — when the treewidth is small. So computing treewidth helps us understand how hard a problem is on a given graph.

For **general graphs**, computing treewidth is NP-hard. But for **split graphs**, there's an efficient formula — which is exactly what your report is about!

---

## 6. The Hammer-Simeone Formula (Theorem 3.1)

This is the core theorem of your report:

$$tw(G) = \max(|C| - 1, \ \max_{v \in I} \deg_C(v))$$

Let's break this down in plain English:

| Symbol | Meaning |
|--------|---------|
| `tw(G)` | Treewidth of the graph G |
| `\|C\|` | Number of vertices in the clique |
| `\|C\| - 1` | One less than the clique size |
| `v ∈ I` | Each vertex v in the independent set |
| `deg_C(v)` | How many clique vertices does v connect to? |
| `max_{v ∈ I} deg_C(v)` | The highest such connection count among all vertices in I |

**In plain English:**
> The treewidth is the bigger of two values:
> 1. The clique size minus 1
> 2. The maximum number of clique-neighbors any independent-set vertex has

**Intuition:**
- The clique is a dense region — naturally contributes `|C| - 1` to the treewidth
- If an independent-set vertex connects to many clique vertices, it "sees" a wide neighborhood, which increases treewidth

---

## 7. Algorithm 1 — Detecting a Split Graph

Before computing treewidth, we first need to **check whether the graph is even a split graph**, and if it is, **identify which vertices belong to C and which belong to I**.

### Step-by-Step Walkthrough

**Input:** A graph G = (V, E)

**Step 1:** Compute the degree of every vertex.
- degree of v = number of edges connected to v

**Step 2:** Sort all vertices from highest degree to lowest degree.
- Result: v₁, v₂, v₃, ..., vₙ (where v₁ has the highest degree)

**Step 3:** Find the largest index `k` such that `deg(vᵢ) ≥ i - 1`
- This means: keep going down the sorted list as long as each vertex has degree ≥ its position minus 1
- This position `k` is where the clique ends

**Step 4:** Define the partition:
- Clique: `C = {v₁, v₂, ..., vₖ}`  (top k vertices by degree)
- Independent Set: `I = {vₖ₊₁, ..., vₙ}` (remaining vertices)

**Step 5:** Verify:
- All vertices in C are connected to each other ✅ (forms a clique?)
- No two vertices in I are connected to each other ✅ (forms an independent set?)

**Step 6:** If both checks pass → the graph IS a split graph. Return (C, I).

### Why does sorting by degree work?

Vertices in a clique must be densely connected, so they naturally have higher degrees. Sorting by degree puts the "busy" (clique) vertices first and the "sparse" (independent set) vertices last. The threshold `deg(vᵢ) ≥ i - 1` is a known mathematical property of clique membership.

---

## 8. Algorithm 2 — Computing the Treewidth

This is a streamlined numerical algorithm that both **verifies** the split graph and **computes** the treewidth using only the degree sequence.

### Step-by-Step Walkthrough

**Step 1:** Compute the degree sequence.
- List the degree of all vertices: d₁, d₂, ..., dₙ

**Step 2:** Sort in **descending** order.
- d₁ ≥ d₂ ≥ d₃ ≥ ... ≥ dₙ

**Step 3:** Find `m`:
$$m = \max\{i \mid d_i \geq i - 1\}$$
- Go through the sorted list; find the last position where the degree is at least (position - 1)
- This gives you the clique size

**Step 4:** Check the split graph condition:
$$\sum_{i=1}^{m} d_i = m(m-1) + \sum_{i=m+1}^{n} d_i$$

**Decoding this formula:**
- Left side: sum of degrees of the top m vertices (the clique vertices)
- Right side:
  - `m(m-1)` = edges within the clique (each of the m vertices connects to m-1 others)
  - `∑ dᵢ` for i > m = sum of degrees of independent set vertices (these are connections from I to C)

This equation checks: "Are all of the clique vertices' edges accounted for by internal clique connections plus connections from I?"

**Step 5:**
- If TRUE → Graph is a split graph. Treewidth = `m - 1`
- If FALSE → Graph is NOT a split graph. This algorithm cannot determine treewidth.

---

## 9. Worked Example 1 — Step by Step

**Setup:**
- Clique: C = {a, b, c}
- Independent Set: I = {d, e}

**Graph edges:**
- a–b, b–c, a–c (clique edges)
- d connects to a and b (degree 2 in C)
- e connects to b and c (degree 2 in C)

**Step 1: Identify the clique size**
$$|C| = k = 3$$

**Step 2: Find deg_C(v) for each v in I**

| Vertex | Connects to clique vertices | deg_C |
|--------|----------------------------|-------|
| d      | a, b                        | 2     |
| e      | b, c                        | 2     |

**Step 3: Find the maximum**
$$\max_{v \in I} \deg_C(v) = \max(2, 2) = 2$$

**Step 4: Apply the formula**
$$tw(G) = \max(|C| - 1, \ 2) = \max(3 - 1, \ 2) = \max(2, 2) = \boxed{2}$$

**✅ Treewidth = 2**

---

## 10. Worked Example 2 — Step by Step

**Setup:**
- Clique: C = {a, b, c, d}
- Independent Set: I = {f}

**Graph edges:**
- a–b, a–c, a–d, b–c, b–d, c–d (all clique edges)
- f connects to a, b, c (but NOT d)

**Step 1: Identify the clique size**
$$|C| = k = 4$$

**Step 2: Find deg_C(v) for each v in I**

| Vertex | Connects to clique vertices | deg_C |
|--------|----------------------------|-------|
| f      | a, b, c                     | 3     |

**Step 3: Find the maximum**
$$\max_{v \in I} \deg_C(v) = 3$$

**Step 4: Apply the formula**
$$tw(G) = \max(|C| - 1, \ 3) = \max(4 - 1, \ 3) = \max(3, 3) = \boxed{3}$$

**✅ Treewidth = 3**

---

## 11. Summary Cheat Sheet

### Key Definitions

| Term | Simple Meaning |
|------|---------------|
| Graph | Dots (vertices) connected by lines (edges) |
| Degree of a vertex | Number of edges connected to it |
| Clique C | Group where everyone is connected to everyone |
| Independent Set I | Group where no one is connected to anyone else in the group |
| Split Graph | Graph = Clique + Independent Set |
| Treewidth | How "complex" a graph is (lower = simpler) |
| deg_C(v) | How many clique-vertices does v in I connect to? |

### The Master Formula

$$\boxed{tw(G) = \max(|C| - 1, \ \max_{v \in I} \deg_C(v))}$$

### Algorithm 2 Quick Reference

```
1. Get degree list → sort descending
2. Find m = last index where d_i ≥ i-1
3. Check: sum(d₁..dₘ) == m(m-1) + sum(dₘ₊₁..dₙ)
4. If TRUE  → split graph, treewidth = m - 1
   If FALSE → not a split graph
```

### Decision Flow

```
Is the graph a split graph?
         |
    YES  |  NO
         |
  Apply  |  This algorithm
 formula |  cannot help
         |
tw(G) = max(|C|-1, max deg_C(v))
```

---

> 📚 **References used in this report:**
> - West, D.B. *Introduction to Graph Theory*, Prentice Hall, 2001
> - Diestel, R. *Graph Theory*, Springer, 2017
