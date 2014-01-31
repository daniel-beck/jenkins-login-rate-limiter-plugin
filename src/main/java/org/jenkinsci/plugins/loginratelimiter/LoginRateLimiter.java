package org.jenkinsci.plugins.loginratelimiter;

import hudson.Extension;
import jenkins.security.SecurityListener;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.userdetails.UserDetails;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.logging.Logger;

@Extension
public class LoginRateLimiter extends SecurityListener {

    private static final Integer RATE_LIMITER_WINDOW_DURATION = Integer.getInteger(LoginRateLimiter.class.getName() + ".duration", 600);
    private static final Integer RATE_LIMITER_MAX_ATTEMPTS = Integer.getInteger(LoginRateLimiter.class.getName() + ".attempts", 3);

    private static class UserLoginFailuresInfo {
        private SortedSet<Date> failures;

        private String name;

        private UserLoginFailuresInfo(String name) {
            failures = Collections.synchronizedSortedSet(new TreeSet<Date>());
            this.name = name;
        }

        public synchronized void recordFailure() {
            LOGGER.fine("Recording login failure for " + name);
            Date now = new Date();
            failures.add(now);

            // remove login failures from earlier than the relevant rate limiting window
            Date ago = new Date(now.getTime());
            ago.setTime(ago.getTime() - RATE_LIMITER_WINDOW_DURATION * 1000);
            failures = failures.tailSet(ago);

            LOGGER.fine("There are now " + failures.size() + " recorded login failures for " + name);
        }

        public synchronized boolean isSevereFailureRate() {
            Date ago = new Date();
            ago.setTime(ago.getTime() - RATE_LIMITER_WINDOW_DURATION * 1000);
            int failureCountInTimeSpan = failures.tailSet(ago).size();

            LOGGER.fine("Determining failure rate for " + name + " at " + failureCountInTimeSpan + " of " + RATE_LIMITER_MAX_ATTEMPTS + " in " + RATE_LIMITER_WINDOW_DURATION + " seconds since: " + ago.toString());

            if (failureCountInTimeSpan >= RATE_LIMITER_MAX_ATTEMPTS) {
                return true;
            }
            return false;
        }
    }

    private Map<String, UserLoginFailuresInfo> failures = new HashMap<String, UserLoginFailuresInfo>();

    // log as SecurityListener to be more visible
    private static final Logger LOGGER = Logger.getLogger(SecurityListener.class.getName());

    @Override
    protected void authenticated(@Nonnull UserDetails userDetails) {
        String name = userDetails.getUsername();
        if (failures.containsKey(name) && failures.get(name).isSevereFailureRate()) {
            LOGGER.warning("LoginRateLimiter prevented login of " + name);
            throw new BadCredentialsException(name);
        }
    }

    @Override
    protected void failedToAuthenticate(@Nonnull String name) {
        if (!failures.containsKey(name)) {
            LOGGER.fine("Initializing login failure info for " + name);
            failures.put(name, new UserLoginFailuresInfo(name));
        }
        failures.get(name).recordFailure();
    }

    @Override
    protected void loggedIn(@Nonnull String name) {
        failures.remove(name);
    }

    @Override
    protected void failedToLogIn(@Nonnull String name) {
        // don't care
    }

    @Override
    protected void loggedOut(@Nonnull String name) {
        // don't care
    }
}

