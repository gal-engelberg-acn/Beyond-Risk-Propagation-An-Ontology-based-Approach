

%------------------------------------------------------
% BAYESIAN NET.
%------------------------------------------------------

0.1::unauthorizedAccess.
0.9::malwareAttack.

0.9::securityAlert :- unauthorizedAccess, malwareAttack.
0.8::securityAlert :- unauthorizedAccess, \+malwareAttack.
0.3::securityAlert :- \+unauthorizedAccess, malwareAttack.
0.1::securityAlert :- \+unauthorizedAccess, \+malwareAttack.

0.6::itAdminCalls :- securityAlert.
0.1::itAdminCalls :- \+securityAlert.

0.9::securityTeamCalls :- securityAlert.
0.2::securityTeamCalls :- \+securityAlert.

%------------------------------------------------------
% FACTS: ENTITIES AND GRAPH STRUCTURE
%------------------------------------------------------

/*
assessor(tom).
assessor(dick).
assessor(harry).
assessor(doctorJ).
*/

event(unauthorizedAccess).
event(malwareAttack).
event(securityAlert).
event(itAdminCalls).
event(securityTeamCalls).

object(itAdmin).
object(securityTeamMember).
object(statefulProtocolAnalysis).
object(cryptoLocker).
object(db_id).
object(voicemailToEmailService).
object(sql_Injection).
object(statefulProtocolAnalysis).

object(emailService_id).
object(network_id).

leads_to(unauthorizedAccess,securityAlert).
leads_to(malwareAttack,securityAlert).
leads_to(securityAlert,itAdminCalls).
leads_to(securityAlert,securityTeamCalls).

participates(db_id,unauthorizedAccess). 
participates(sql_Injection,unauthorizedAccess). 
participates(db_id,malwareAttack). 
participates(cryptoLocker,malwareAttack). 
participates(securityTeamMember,securityTeamCalls).
participates(itAdmin,itAdminCalls).
participates(voicemailToEmailService,itAdminCalls).
participates(statefulProtocolAnalysis,securityAlert).

capability(dbConfidentiality).
capability(dbIntegrity).
capability(healthyWorkload).
capability(emIntegrity).

intendedCapability(harry,db_id,dbConfidentiality).
intendedCapability(harry,db_id,dbIntegrity).
intendedCapability(harry,securityTeamMember,healthyWorkload).
intendedCapability(harry,emailService_id,emIntegrity).

controlMechanism(emailSecurity).
controlMechanism(hostBasedAntiRansomware).
controlMechanism(sensitiveInfoEncryption).
controlMechanism(ueba).
controlMechanism(null).

%------------------------------------------------------
% FACTS: COMPUTED VALUES
%------------------------------------------------------ 

likelihoodAssessor(LA) :- likelihoodComputedValue(E,V,LA).

likelihoodComputedValue(unauthorizedAccess,V,tom) :- subquery(unauthorizedAccess,V), assessor(tom).
likelihoodComputedValue(malwareAttack,V,tom) :- subquery(malwareAttack,V), assessor(tom).
likelihoodComputedValue(securityAlert,V,tom) :- subquery(securityAlert,V), assessor(tom).
likelihoodComputedValue(itAdminCalls,V,tom) :- subquery(itAdminCalls,V), assessor(tom).
likelihoodComputedValue(securityTeamCalls,V,tom) :- subquery(securityTeamCalls,V), assessor(tom).

likelihoodComputedValue(unauthorizedAccess,V,dick) :- V is 0.55.
likelihoodComputedValue(malwareAttack,V,dick) :- V is 0.85.
likelihoodComputedValue(securityAlert,V,dick) :- V is 0.6.
likelihoodComputedValue(itAdminCalls,V,dick) :- V is 0.65.
likelihoodComputedValue(securityTeamCalls,V,dick) :- V is 0.5.
/* to avoid implementing an additional net for dick */

likelihoodComputedValue(unauthorizedAccess,V,harry) :- V is 0.7.
likelihoodComputedValue(malwareAttack,V,harry) :- V is 0.8.
likelihoodComputedValue(securityAlert,V,harry) :- V is 0.76.
likelihoodComputedValue(itAdminCalls,V,harry) :- V is 0.4.
likelihoodComputedValue(securityTeamCalls,V,harry) :- V is 0.2.
/* to avoid implementing an additional net for harry */

/* scale (continuous): [0-1] */

%------------------------------------------------------

vulnerabilityAssessor(VA) :- vulnerabilityComputedValue(E,O,G,V,VA).

vulnerabilityComputedValue(malwareAttack,db_id,dbIntegrity,V,harry) :- V = 4.
vulnerabilityComputedValue(malwareAttack,db_id,dbConfidentiality,V,harry) :- V = 5.
vulnerabilityComputedValue(unauthorizedAccess,db_id,dbIntegrity,V,harry) :- V = 8.
vulnerabilityComputedValue(unauthorizedAccess,db_id,dbConfidentiality,V,harry) :- V = 9.

vulnerabilityComputedValue(securityTeamCalls,securityTeamMember,healthyWorkload,V,harry) :- V = 10.

/* UPDATE !!! scale (discrete): {negligible[1], low[2], middle[3], high[4], very high[5]} */

%------------------------------------------------------

mitigationAssessor(MA) :- mitigationComputedValue(E,O,G,CM,C,MA,V).

% mitigationComputedValue(malwareAttack,db_id,dbIntegrity,emailSecurity,C,harry,V) :- V = 3, C = 9.
mitigationComputedValue(malwareAttack,emailService_id,emIntegrity,emailSecurity,C,harry,V) :- V = 2.5, C = 8.5.

mitigationComputedValue(malwareAttack,db_id,dbIntegrity,hostBasedAntiRansomware,C,harry,V) :- V = 8, C = 9.
mitigationComputedValue(malwareAttack,db_id,dbConfidentiality,sensitiveInfoEncryption,C,harry,V) :- V = 10, C = 10.
mitigationComputedValue(malwareAttack,db_id,dbConfidentiality,ueba,C,harry,V) :- V = 2, C = 4.

mitigationComputedValue(unauthorizedAccess,db_id,dbIntegrity,sensitiveInfoEncryption,C,harry,V) :- V = 10, C = 10.
mitigationComputedValue(unauthorizedAccess,db_id,dbIntegrity,ueba,C,harry,V) :- V = 2, C = 4.
mitigationComputedValue(unauthorizedAccess,db_id,dbConfidentiality,emailSecurity,C,harry,V) :- V = 4, C = 9.
mitigationComputedValue(unauthorizedAccess,db_id,dbConfidentiality,hostBasedAntiRansomware,C,harry,V) :- V = 8, C = 9.

mitigationComputedValue(securityTeamCalls,securityTeamMember,healthyWorkload,null,C,harry,V) :- V = 1, C = 1.

/*
mitigationComputedValue(malwareAttack,db_id,dbIntegrity,emailSecurity,C,harry,V) :- V = 3, C = 9.
mitigationComputedValue(malwareAttack,db_id,dbIntegrity,hostBasedAntiRansomware,C,harry,V) :- V = 8, C = 9.
mitigationComputedValue(malwareAttack,db_id,dbIntegrity,sensitiveInfoEncryption,C,harry,V) :- V = 10, C = 10.
mitigationComputedValue(malwareAttack,db_id,dbIntegrity,ueba,C,harry,V) :- V = 2, C = 4.

mitigationComputedValue(malwareAttack,db_id,dbConfidentiality,emailSecurity,C,harry,V) :- V = 3, C = 9.
mitigationComputedValue(malwareAttack,db_id,dbConfidentiality,hostBasedAntiRansomware,C,harry,V) :- V = 8, C = 9.
mitigationComputedValue(malwareAttack,db_id,dbConfidentiality,sensitiveInfoEncryption,C,harry,V) :- V = 10, C = 10.
mitigationComputedValue(malwareAttack,db_id,dbConfidentiality,ueba,C,harry,V) :- V = 2, C = 4.

mitigationComputedValue(unauthorizedAccess,db_id,dbIntegrity,emailSecurity,C,harry,V) :- V = 4, C = 9.
mitigationComputedValue(unauthorizedAccess,db_id,dbIntegrity,hostBasedAntiRansomware,C,harry,V) :- V = 8, C = 9.
mitigationComputedValue(unauthorizedAccess,db_id,dbIntegrity,sensitiveInfoEncryption,C,harry,V) :- V = 10, C = 10.
mitigationComputedValue(unauthorizedAccess,db_id,dbIntegrity,ueba,C,harry,V) :- V = 2, C = 4.

mitigationComputedValue(unauthorizedAccess,db_id,dbConfidentiality,emailSecurity,C,harry,V) :- V = 4, C = 9.
mitigationComputedValue(unauthorizedAccess,db_id,dbConfidentiality,hostBasedAntiRansomware,C,harry,V) :- V = 8, C = 9.
mitigationComputedValue(unauthorizedAccess,db_id,dbConfidentiality,sensitiveInfoEncryption,C,harry,V) :- V = 10, C = 10.
mitigationComputedValue(unauthorizedAccess,db_id,dbConfidentiality,ueba,C,harry,V) :- V = 2, C = 4.
*/

/* TO BE UPDATEDs !!! scale (discrete): {negligible[1], low[2], middle[3], high[4], very high[5]} */

%------------------------------------------------------

impactAssessor(IA) :- impactComputedValue(E,O,G,[VV,MV],IA,IV).

impactComputedValue(E,O,G,[VV,MV],tom,IV) :- vulnerabilityComputedValue(E,O,G,VV,VA), mitigationComputedValue(E,O,G,CM,C,MA,MV), IV is ((VV - MV) +9)/18. 
impactComputedValue(E,O,G,[VV,MV],dick,IV) :- vulnerabilityComputedValue(E,O,G,VV,VA), mitigationComputedValue(E,O,G,CM,C,MA,MV), IV is ((VV - MV) +9)/18. 
impactComputedValue(E,O,G,[VV,MV],harry,IV) :- vulnerabilityComputedValue(E,O,G,VV,VA), mitigationComputedValue(E,O,G,CM,C,MA,MV), IV is ((VV - MV) +9)/18. 
impactComputedValue(E,O,G,[VV,MV],doctorJ,IV) :- vulnerabilityComputedValue(E,O,G,VV,VA), mitigationComputedValue(E,O,G,CM,C,MA,MV), IV is ((VV - MV) +9)/18.

/* scale (continuous): [0-1] */

%------------------------------------------------------

riskAssessor(RA) :- riskComputedValue(E,O,G,[LV,IV],RA,RV).

riskComputedValue(E,O,G,[LV,IV],tom,RV) :- likelihoodComputedValue(E,LV,LA), impactComputedValue(E,O,G,[VV,MV],IA,IV), RV is LV * IV.          
riskComputedValue(E,O,G,[LV,IV],dick,RV) :- likelihoodComputedValue(E,LV,LA), impactComputedValue(E,O,G,[VV,MV],IA,IV), RV is LV * IV.          
riskComputedValue(E,O,G,[LV,IV],harry,RV) :- likelihoodComputedValue(E,LV,LA), impactComputedValue(E,O,G,[VV,MV],IA,IV), RV is LV * IV.
riskComputedValue(E,O,G,[LV,IV],doctorJ,RV) :- likelihoodComputedValue(E,LV,LA), impactComputedValue(E,O,G,[VV,MV],IA,IV), RV is LV * IV.

%------------------------------------------------------
%------------------------------------------------------

/* ***TO BE FIXED*** 
out:
implementedOnObject(emailSecurity,emailService_id).
implementedOnObject(sensitiveInfoEncryption,db_id).
implementedOnObject(null,securityTeamMember).
implementedOnObject(null,cryptoLocker).
implementedOnObject(null,sql_Injection).
implementedOnObject(hostBasedAntiRansomware,db_id).
implementedOnObject(ueba,db_id).


partOf(db_id,network_id).
partOf(emailService_id,network_id).

contributesFor(O2,O1,G) :- intendedCapability(A,O1,G), partOf(O1,O), partOf(O2,O), O1 \= O2.
contributesFor(O,O,G) :- intendedCapability(A,O,G).
this should be "has role in"
by definition: everything contributesFor to itself, no matter the capability considered

mitigationAssessment(E,O,G,CM,C,A,V) :- event(E), object(O), object(O1), capability(G), controlMechanism(CM), assessor(A), assessor(A1), intendedCapability(A1,O,G), implementedOnObject(CM,O1), mitigationComputedValue(E,O1,G,CM,C,A,V).
*/


%------------------------------------------------------                   
% RULES.
%------------------------------------------------------

assessor(LA) :- likelihoodAssessor(LA).
assessor(VA) :- vulnerabilityAssessor(VA).
assessor(MA) :- mitigationAssessor(MA).
assessor(IA) :- impactAssessor(IA).
assessor(RA) :- riskAssessor(RA).

object(O) :- controlMechanism(O).
event(E) :- riskyEvent(E,O,G).

participates(O,E) :- object(O), event(E), has_participant(E,O).
has_participant(O,E) :- object(O), event(E), participantOf(O,E).

leads_to(E1,E2) :- event(E1), event(E2), dependsOn(E2,E1), E1 \= E2.
dependsOn(E1,E2) :- event(E1), event(E2), leads_to(E2,E1), E1 \= E2.

intendedCapability(A,O,G) :- assessor(A), object(O), capability(G), ascribedCapability(G,O,A).
ascribedCapability(A,O,G) :- assessor(A), object(O), capability(G), intendedCapability(A,O,G).

likelihoodAssessment(E,A,V) :- event(E), assessor(A), likelihoodComputedValue(E,V,A).

vulnerabilityAssessment(E,O,G,A,V) :- event(E), object(O), assessor(A), participates(O,E), intendedCapability(A,O,G), vulnerabilityComputedValue(E,O,G,V,A).

mitigationAssessment(E,O,G,CM,C,A,V) :- object(O), controlMechanism(CM), capability(G), assessor(A), intendedCapability(A,O,G), mitigationComputedValue(E,O,G,CM,C,A,V).

impactAssessment(E,O,G,IA,IV) :- vulnerabilityAssessment(E,O,G,VA,VV), mitigationAssessment(E,O,G,CM,C,MA,MV), impactComputedValue(E,O,G,[VV,MV],IA,IV).

riskAssessment(E,O,G,RA,RV) :- impactAssessment(E,O,G,IA,IV), likelihoodAssessment(E,A,V), riskComputedValue(E,O,G,[LV,IV],RA,RV).

riskyEvent(E,O,G) :- riskAssessment(E,O,G,RA,RV), RV > 0.5.
atRiskObject(E,O,G) :- riskAssessment(E,O,G,RA,RV), RV > 0.5.

vulnerable(E,O,G) :- vulnerabilityAssessment(E,O,G,A,V), V > 8.

%%%    ***TO BE FIXED*** eventRiskAssessor(E,O,G,L) :- event(E), object(O), capability(G), findall(RA,riskAssessment(unauthorizedAccess,db_id,dbConfidentiality,RA,RV),L).

%------------------------------------------------------                   
% QUERIES.
%------------------------------------------------------

%      query(likelihoodComputedValue(securityAlert,V,X)).
%      query(mitigationComputedValue(securityTeamCalls,securityTeamMember,healthyWorkload,CM,C,MA,V)).
%      query(vulnerabilityComputedValue(unauthorizedAccess,db_id,dbIntegrity,tom,V)).
%      query(impactComputedValue(E,O,G,[VV,MV],IA,IV)).
%      query(impactComputedValue(securityTeamCalls,O,G,[VV,MV],IA,IV)).
%      query(impactComputedValue(unauthorizedAccess,db_id,dbIntegrity,[VV,MV],emailSecurity,IA,IV)).
%      query(impactComputedValue(malwareAttack,db_id,dbIntegrity,[VV,MV],A,IV)).
%      query(impactComputedValue(malwareAttack,db_id,dbConfidentiality,[VV,MV],A,IV)).
%      query(riskComputedValue(malwareAttack,O,G,[LV,IV],RA,RV)).
%      query(riskComputedValue(E,O,G,[LV,IV],CM,LA,tom,RV)).
%      query(riskComputedValue(securityTeamCalls,O,G,[LV,IV],RA,RV)).
%      query(riskComputedValue(malwareAttack,O,dbIntegrity,[LV,IV],RA,RV)).
%      query(riskComputedValue(malwareAttack,O,dbConfidentiality,[LV,IV],RA,RV)).
%      query(riskComputedValue(securityTeamCalls,securityTeamMember,healthyWorkload,[LV,1.0],harry,0.5668)).
%      query(riskComputedValue(securityTeamCalls,O,G,[LV,IV],CM,LA,IA,RV)).
%      query(riskComputedValue(securityTeamCalls,securityTeamMember,healthyWorkload,[LV,IV],CM,LA,doctorJ,RV)).
%      query(riskComputedValue(unauthorizedAccess,db_id,dbConfidentiality,[LV,IV],CM,LA,IA,RV)).

%      query(likelihoodAssessment(securityTeamCalls,tom,V)).
%      query(likelihoodAssessment(securityTeamCalls,A,V)).
%      query(likelihoodAssessment(unauthorizedAccess,A,V)).
%      query(vulnerabilityAssessment(E,O,G,A,V)).
%      query(vulnerabilityAssessment(E,cryptoLocker,G,A,V)).
%      query(vulnerabilityAssessment(unauthorizedAccess,db_id,dbIntegrity,A,V)).
       query(mitigationAssessment(E,O,G,CM,C,A,V)).
%      query(mitigationAssessment(securityTeamCalls,O,G,CM,C,A,V)).
%      query(mitigationAssessment(itAdminCalls,O,G,CM,C,A,V)).
%      query(mitigationAssessment(unauthorizedAccess,O,G,CM,C,A,V)).
%      query(mitigationAssessment(malwareAttack,O,G,CM,C,A,V)).
%      query(mitigationAssessment(securityAlert,O,G,CM,C,A,V)).
%      query(impactAssessment(E,O,G,IA,IV)).
%      query(impactAssessment(securityTeamCalls,securityTeamMember,healthyWorkload,IA,IV)).
%      query(impactAssessment(malwareAttack,cryptoLocker,G,IA,IV)).
%      query(impactAssessment(unauthorizedAccess,db_id,dbIntegrity,IA,IV)).
%      query(riskAssessment(E,O,G,RA,RV)).
%      query(riskAssessment(malwareAttack,O,G,RA,RV)).
%      query(riskAssessment(securityTeamCalls,securityTeamMember,healthyWorkload,RA,RV)).
%      query(riskAssessment(securityTeamCalls,securityTeamMember,healthyWorkload,tom,RV)).
%      query(riskAssessment(unauthorizedAccess,db_id,dbConfidentiality,RA,RV)).
%%%    ***TO BE FIXED*** query(eventRiskAssessor(E,O,G,L)).

/* --- "participant_object_list" --- */
%      list_object(E1,E2,L) :- dependsOn(E1,E2), findall(O,participates(O,E2),L).
%      query(list_object(E1,E2,L)).

/* --- "at risk/risky" --- */
%      query(atRiskObject(E,O,G)).
%      query(riskyEvent(E,O,G)).
%      query(vulnerable(E,O,G)).

%      query(likelihoodAssessment(securityTeamCalls,A,V)).

%      query(contributesFor(O1,O,G)).
%      query(implementedOnObject(X,Y)).
%      query(event(E)).
%      query(assessor(A)).
