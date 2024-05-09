## Risk Propagation Queries

Given a risk propagation graph, representing a system composed of connected objects (directly or indirectly), their risk enabler (vulnerabilities, configurations), participation in threat events, and loss events (with regards to multiple levels of organizational values or missions, as availability of service, profitability, and more)  

Which of the following queries are part of a risk assessment?

### Risk quantification & propagation

**Risk quantification**

- What is the probability of a risk event occurring in the system?
- What is the expected loss associated with a particular risk event?
- What is the severity and exploitability (likelihood to be exploited as part of a threat event) of each vulnerability within the system?

**Propagation of risk between entities**

- How risk of event X affects the risk of event Y?
- What is the risk of an object, given the event(s) in which it participates?
- What is the risk of an event, given the event(s) to which it is connected?
- What is the risk of an object, given the object(s) to which it is connected?
- What is the risk of an event, sharing an object with other events?
- What is the risk of an object in an event with another object, which is in another event?
- What is the risk of an event, given different properties characterizing the correlated event?
- What is the likelihood of a risk event triggering multiple other risk events in the system?
- What are the different pathways that a risk can take as it propagates through the system?
- What is the most likely path for a risk to propagate through the system?
- What is the critical path of influence in the risk network for system value loss?
- How does the severity of a risk changes as it propagates through the system?
- How do dependencies between different system components affect the propagation of risk?
- What are the components that are most likely to be affected by the propagation of risk?
- What are the most vulnerable points in the system that are likely to amplify the propagation of risk?
- How do changes in the system affect the propagation of risk?
- What is the forward-looking prediction of risk propagation from one risk event to another?

### Risk propagation –impact over missions and values

- What is the global impact of a risk event to the system? (e.g., system shutdown)
- What is the likelihood of a risk event causing a significant global impact on the system? (Given a clear definition of what is a significant impact)
- What are the potential loss events over objects and their missions and values (e.g., mission's operability) enabled by a specific vulnerability or system configuration? [using following dependencies: flow inter-dependency, Multiple Tasks to Single Host 'AND' Inter-dependency, Single Task to Multiple Host 'AND' Inter-dependency, Single Task to Multiple Hosts 'OR' Inter-dependency, Single Task to Single Host 'FLOW' Inter-dependency and Task to Task Intra-dependency]
- What is the risk propagation quantification: the materialization of risks which first impacts one operational asset, then, impacts other correlated operational assets. What is the level of direct and indirect dependencies?
- What risk event has the highest effect on the risk propagation through the system?
- What is the most influential risk event over system's higher-level value?
- How risks propagate to influence system's higher-level value?
- What is the impact of specific risk events on business level values?
- What are the dependencies between different system values? (e.g., supply discontinuity, quality inconsistency, delivery delay, and customer value risk)
- What is the impact of state disposition of system values (e.g., supply discontinuity) over other system's value (e.g., profitability)
- What is the effect of eliminating facts from the graph over the risk assessment? (Vulnerability repair, configuration change, device removal, etc.,)
- What is the risk quantification on average disruptive events?
- What is the risk quantification on severe events?

### Risk mitigation

- What are the available options for mitigating a specific risk in the system?
- How effective is a specific mitigation action in reducing risk?
- What are the costs associated with implementing a specific mitigation action?
- What is the best combination of mitigation actions to reduce overall risk in the system?
- What is the minimum set of mitigation actions required to achieve a specific level of risk reduction in the system?
- How can we prioritize mitigation actions based on their effectiveness and cost?
- What are the trade-offs between different mitigation actions in terms of effectiveness, cost, and impact on the system?
- What is the critical path of influence in the risk network for the backward-looking traceability of risk root causes?
- What is the risk root causes for predefined loss events (for example, supply discontinuity, quality consistency, and delivery delay)
