package net.continuumsecurity.utils;

/**
 * Created by stephen on 12/04/2014.
 */
public class TestResult {
    boolean vulnerable;
    String details;

    public boolean isVulnerable() {
        return vulnerable;
    }

    public void setVulnerable(boolean vulnerable) {
        this.vulnerable = vulnerable;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public void addDetails(String detail, String delimiter) {
        if (getDetails() != null) {
            setDetails(getDetails()+delimiter+detail);
        } else setDetails(detail);
    }
}
