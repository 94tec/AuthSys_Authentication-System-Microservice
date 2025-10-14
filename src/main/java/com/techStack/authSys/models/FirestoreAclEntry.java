package com.techStack.authSys.models;


import com.google.cloud.spring.data.firestore.Document;
import org.springframework.data.annotation.Id;

import java.util.HashSet;
import java.util.Set;

@Document(collectionName = "acl_entries")
public class FirestoreAclEntry {

    @Id
    private String id;
    private String objectId;
    private String principal;
    private Set<String> permissions = new HashSet<>();

    public FirestoreAclEntry() {}

    public FirestoreAclEntry(String objectId, String principal) {
        this.objectId = objectId;
        this.principal = principal;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getObjectId() { return objectId; }
    public void setObjectId(String objectId) { this.objectId = objectId; }

    public String getPrincipal() { return principal; }
    public void setPrincipal(String principal) { this.principal = principal; }

    public Set<String> getPermissions() { return permissions; }
    public void setPermissions(Set<String> permissions) { this.permissions = permissions; }
}
