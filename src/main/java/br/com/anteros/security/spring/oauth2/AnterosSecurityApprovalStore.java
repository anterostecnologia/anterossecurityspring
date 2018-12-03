package br.com.anteros.security.spring.oauth2;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.stereotype.Component;

import br.com.anteros.security.store.SecurityDataStore;

@Component("approvalStore")
public class AnterosSecurityApprovalStore implements ApprovalStore {
	
	@Autowired
	private SecurityDataStore securityDataStore;

	public boolean addApprovals(Collection<Approval> approvals) {
		securityDataStore.addApprovals(approvals);
		return true;
	}

	public boolean revokeApprovals(Collection<Approval> approvals) {
		securityDataStore.revokeApprovals(approvals);
		return true;
	}

	public Collection<Approval> getApprovals(String userId, String clientId) {
		return securityDataStore.getApprovals(userId,clientId);
	}
	



}
