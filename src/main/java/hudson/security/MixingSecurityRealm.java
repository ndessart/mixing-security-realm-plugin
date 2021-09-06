package hudson.security;

import groovy.lang.Binding;
import hudson.*;
import hudson.cli.CLICommand;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.security.SecurityRealm.SecurityComponents;
import hudson.security.captcha.CaptchaSupport;
import hudson.util.spring.BeanBuilder;
import jenkins.model.Jenkins;
import jenkins.security.ImpersonatingUserDetailsService;
import jenkins.security.SecurityListener;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jenkinsci.Symbol;
import org.kohsuke.args4j.Option;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.logging.Logger;

@SuppressWarnings("unused")
public class MixingSecurityRealm extends HudsonPrivateSecurityRealm {

    private static final Logger logger = Logger.getLogger(MixingSecurityRealm.class.getName());

    private List<SecurityRealm> optionals = new ArrayList<>();
    private boolean priority;

    @DataBoundConstructor
    public MixingSecurityRealm(boolean allowsSignup, boolean enableCaptcha, CaptchaSupport captchaSupport, boolean priority) {
        super(allowsSignup, enableCaptcha, captchaSupport);
        this.priority = priority;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    /**
     * 判定用户是否是Jenkins私有用户
     *
     * @param username 用户名
     * @return 是否是私有用户
     */
    public boolean isPrivateUser(String username) {
        User u = User.getById(username, false);
        return u != null && u.getProperty(Details.class) != null;
    }

    public static boolean isOwnedBy(String username, UserDetailsService service) {
        try {
            return service.loadUserByUsername(username) != null;
        } catch (UsernameNotFoundException ignore) {
            return false;
        }
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        Binding binding = new Binding();
        binding.setVariable("authenticator", new Authenticator());
        BeanBuilder builder = new BeanBuilder();
        builder.parse(Jenkins.get().servletContext.getResourceAsStream("/WEB-INF/security/AbstractPasswordBasedSecurityRealm.groovy"), binding);
        WebApplicationContext context = builder.createApplicationContext();
        SecurityComponents securityComponents = new SecurityComponents(
                findBean(AuthenticationManager.class, context),
                new ImpersonatingUserDetailsService(this));
        if (optionals == null) return securityComponents;
        Map<SecurityRealm, SecurityComponents> securityComponentsMap = new HashMap<>();
        for (SecurityRealm securityRealm : optionals) {
            securityComponentsMap.put(securityRealm, securityRealm.createSecurityComponents());
        }

        return new SecurityComponents(
            new MixinAuthenticationManager(securityComponents, securityComponentsMap),
            new MixinUserDetailsService(securityComponents, securityComponentsMap)
        );
    }

    private class MixinAuthenticationManager implements AuthenticationManager {
        private SecurityComponents securityComponents;
        Map<SecurityRealm, SecurityComponents> securityComponentsMap;

        MixinAuthenticationManager(SecurityComponents securityComponents,
                Map<SecurityRealm, SecurityComponents> securityComponentsMap) {
            this.securityComponents = securityComponents;
            this.securityComponentsMap = securityComponentsMap;
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            String name = authentication.getName();
            Authentication authentication2 = null;
            if (priority && authentication2 == null) {
                authentication2 = authenticateLocal(name, authentication);
            }
            if (authentication2 == null) {
                authentication2 = authenticateOptionals(name, authentication);
                ;
            }
            if (!priority && authentication2 == null) {
                authentication2 = authenticateLocal(name, authentication);
            }

            if (authentication2 == null) {
                throw new UsernameNotFoundException("Not found in any realm: " + name);
            }
            return authentication2;
        }

        private Authentication authenticateLocal(String name, Authentication authentication) {
            if (isPrivateUser(name)) {
                logger.fine("SecurityComponents.authentication.isPrivateUser => " + name);
                return securityComponents.manager.authenticate(authentication);
            }
            return null;
        }

        private Authentication authenticateOptionals(String name, Authentication authentication) {
            for (SecurityRealm securityRealm : optionals) {
                SecurityComponents components = securityComponentsMap.get(securityRealm);
                if (isOwnedBy(name, components.userDetails)) {
                    logger.fine("SecurityComponents.authentication.isOwnedBy => " + name + " -> " + securityRealm);
                    return components.manager.authenticate(authentication);
                }
            }
            return null;
        }
    }

    private class MixinUserDetailsService implements UserDetailsService {
        private SecurityComponents securityComponents;
        Map<SecurityRealm, SecurityComponents> securityComponentsMap;

        MixinUserDetailsService(SecurityComponents securityComponents,
        Map<SecurityRealm, SecurityComponents> securityComponentsMap){
            this.securityComponents = securityComponents;
            this.securityComponentsMap = securityComponentsMap;
        }

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            {
                if (priority) {
                    try {
                        return loadUserByUsernameLocal(username);
                    } catch (UsernameNotFoundException e) {
                        UserDetails ud = loadUserByUsernameOptionals(username);
                        if (ud == null) {
                            throw e;
                        }
                        
                        return ud;
                    }
                } else {
                    UserDetails ud = loadUserByUsernameOptionals(username);

                    if(ud == null) {
                        ud = loadUserByUsernameLocal(username);
                    }
                    return ud;
                }
            }
        }

        private UserDetails loadUserByUsernameLocal(String username) {
            logger.fine("SecurityComponents.loadUserByUsername.isPrivateUser => " + username);
            return securityComponents.userDetails.loadUserByUsername(username);
        }

        private UserDetails loadUserByUsernameOptionals(String username) {
            for (SecurityRealm securityRealm : optionals) {
                SecurityComponents components = securityComponentsMap.get(securityRealm);
                try {
                    logger.fine("SecurityComponents.loadUserByUsername.isOwnedBy => " + username + " -> "
                            + securityRealm);
                    return components.userDetails.loadUserByUsername(username);
                } catch (UsernameNotFoundException ignore) {
                }
            }
            return null;
        }
    }

    public static Details fromUserDetail(UserDetails userDetails) {
        return proxyDetail(userDetails.getUsername(), null);
    }

    public static String emptyPassword() {
        return null;
    }

    public static Details proxyDetail(String username, User user) {
        try {
            Constructor<Details> constructor = Details.class.getDeclaredConstructor(String.class);
            constructor.setAccessible(true);
            Details details = constructor.newInstance(emptyPassword());
            if (user == null) {
                user = User.getOrCreateByIdOrFullName(username);
            }
            Method method = UserProperty.class.getDeclaredMethod("setUser", User.class);
            method.setAccessible(true);
            method.invoke(details, user);
            return details;
        } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new UsernameNotFoundException(e.getMessage(), e);
        }
    }

    @Override
    public Details loadUserByUsername(String username) {
        if (this.priority) {
            try {
                return super.loadUserByUsername(username);
            } catch (UsernameNotFoundException e) {
                for (SecurityRealm realm : optionals) {
                    try {
                        return fromUserDetail(realm.loadUserByUsername(username));
                    } catch (UsernameNotFoundException ignore) {
                    }
                }
                throw e;
            }
        } else {
            for (SecurityRealm realm : optionals) {
                try {
                    return fromUserDetail(realm.loadUserByUsername(username));
                } catch (UsernameNotFoundException ignore) {
                }
            }
            return super.loadUserByUsername(username);
        }
    }

    @SuppressWarnings("deprecation")
    public CliAuthenticator createCliAuthenticator(final CLICommand command) {
        CliAuthenticator authenticator = super.createCliAuthenticator(command);
        return new CliAuthenticator() {

            @Option(name = "--username", usage = "User name to authenticate yourself to Jenkins")
            public String userName;

            @Option(name = "--password", usage = "Password for authentication. Note that passing a password in arguments is insecure.")
            public String password;

            @Option(name = "--password-file", usage = "File that contains the password")
            public String passwordFile;

            CliAuthenticator fillFields(CliAuthenticator authenticator) throws AuthenticationException {
                for (Field field : authenticator.getClass().getDeclaredFields()) {
                    try {
                        if (field.getName().equalsIgnoreCase("userName")) {
                            field.set(authenticator, userName);
                        } else if (field.getName().equalsIgnoreCase("password")) {
                            field.set(authenticator, password);
                        } else if (field.getName().equalsIgnoreCase("passwordFile")) {
                            field.set(authenticator, passwordFile);
                        }
                    } catch (IllegalAccessException e) {
                        throw new AuthenticationException(e.getMessage(), e) {
                        };
                    }
                }
                return authenticator;
            }

            public Authentication authenticate() throws AuthenticationException, IOException, InterruptedException {
                if (userName == null)
                    return command.getTransportAuthentication();
                if (priority) {
                    if (isPrivateUser(userName)) {
                        fillFields(authenticator);
                        logger.fine("Authentication.authenticate.isPrivateUser => " + userName);
                        return authenticator.authenticate();
                    } else {
                        for (SecurityRealm securityRealm : optionals) {
                            try {
                                securityRealm.loadUserByUsername(userName);
                                logger.fine("Authentication.authenticate.isOwnedBy => " + userName + " -> " + securityRealm);
                                return fillFields(securityRealm.createCliAuthenticator(command)).authenticate();
                            } catch (UsernameNotFoundException ignore) {
                            }
                        }
                        throw new UsernameNotFoundException("Not found in any realm");
                    }
                } else {
                    for (SecurityRealm securityRealm : optionals) {
                        try {
                            securityRealm.loadUserByUsername(userName);
                            logger.fine("Authentication.authenticate.isOwnedBy => " + userName + " -> " + securityRealm);
                            return fillFields(securityRealm.createCliAuthenticator(command)).authenticate();
                        } catch (UsernameNotFoundException ignore) {
                        }
                    }
                    fillFields(authenticator);
                    logger.fine("Authentication.authenticate.isPrivateUser => " + userName);
                    return authenticator.authenticate();
                }
            }
        };
    }

    class Authenticator extends AbstractUserDetailsAuthenticationProvider {
        protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
            // authentication is assumed to be done already in the retrieveUser method
        }

        protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
            return doAuthenticate(username, authentication.getCredentials().toString());
        }
    }

    private Details selfAuthenticate(String username, String password) {
        Details u = super.loadUserByUsername(username);
        if (!u.isPasswordCorrect(password)) {
            String message = this.getLocalizedBadCredentialsMessage();
            throw new BadCredentialsException(message);
        }
        
        return u;
    }

    private String getLocalizedBadCredentialsMessage() {
        try {
            return ResourceBundle.getBundle("org.acegisecurity.messages").getString("AbstractUserDetailsAuthenticationProvider.badCredentials");
        } catch (MissingResourceException x) {
            /* Expected if localisation string not present */
        }

        return "Bad credentials";
    }

    @Override
    protected Details authenticate(String username, String password) throws AuthenticationException {
        if (priority) {
            if (isPrivateUser(username)) {
                logger.fine("authenticate.isPrivateUser => " + username);
                return selfAuthenticate(username, password);
            } else {
                for (SecurityRealm realm : optionals) {
                    try {
                        logger.fine("authenticate.isOwnedBy => " + username + " -> " + realm);
                        return fromUserDetail(realm.loadUserByUsername(username));
                    } catch (UsernameNotFoundException ignore) {
                    }
                }
            }
        } else {
            for (SecurityRealm realm : optionals) {
                try {
                    logger.fine("authenticate.isOwnedBy => " + username + " -> " + realm);
                    return fromUserDetail(realm.loadUserByUsername(username));
                } catch (UsernameNotFoundException ignore) {
                }
            }
            logger.fine("authenticate.isPrivateUser => " + username);
            return selfAuthenticate(username, password);
        }
        throw new UsernameNotFoundException("Not found in any realm: " + username);
    }

    private UserDetails doAuthenticate(String username, String password) throws AuthenticationException {
        try {
            logger.fine("doAuthenticate => " + username);
            Details user = authenticate(username, password);
            SecurityListener.fireAuthenticated(user);
            return user;
        } catch (AuthenticationException x) {
            SecurityListener.fireFailedToAuthenticate(username);
            throw x;
        }
    }

    @Extension
    @Symbol("password")
    public static final class UserDescriptorImpl extends UserPropertyDescriptor {

        static Details.DescriptorImpl descriptor;

        static {
            // 替换原有的UserPropertyDescriptor
            DescriptorExtensionList<UserProperty, UserPropertyDescriptor> extensionList = Jenkins.get().getDescriptorList(UserProperty.class);
            for (UserPropertyDescriptor d : extensionList) {
                if (d.getClass() == Details.DescriptorImpl.class) {
                    extensionList.remove(d);
                    descriptor = (Details.DescriptorImpl) d;
                    break;
                }
            }
        }

        public UserDescriptorImpl() {
            super(Details.class);
        }

        @Nonnull
        public String getDisplayName() {
            return "Password";
        }

        @Override
        public UserProperty newInstance(StaplerRequest req, @Nonnull JSONObject formData) throws FormException {
            if (req == null) {
                return super.newInstance(null, formData);
            }
            User user = req.findAncestorObject(User.class);
            if (user == null) {
                throw new IllegalArgumentException("No ancestor of type User in the request");
            }
            if (user.getProperty(Details.class) != null) {
                logger.fine("UserDescriptorImpl.newInstance.isPrivateUser => " + user.getId());
                return descriptor.newInstance(req, formData);
            }
            logger.fine("UserDescriptorImpl.newInstance.isOwnedByOther => " + user.getId());
            return proxyDetail(user.getId(), user);
        }

        @Override
        public boolean isEnabled() {
            return Jenkins.get().getSecurityRealm() instanceof MixingSecurityRealm;
        }

        @Override
        public UserProperty newInstance(User user) {
            logger.fine("UserDescriptorImpl.newInstance.null => " + user);
            return null;
        }

        public boolean hasDetails(Details details) {
            if (details == null) return false;
            try {
                Method getUser = Details.class.getDeclaredMethod("getUser");
                getUser.setAccessible(true);
                User user = (User) getUser.invoke(details);
                return user.getProperty(Details.class) != null;
            } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
                return false;
            }
        }

    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public final List<SecurityRealm> optionals = new ArrayList<>();

        public DescriptorImpl() {
            super();
            load();
        }

        public String getDisplayName() {
            return "Mixing";
        }

        public SecurityRealm getInstance(Descriptor<SecurityRealm> descriptor) {
            if (descriptor == null) return null;
            for (SecurityRealm securityRealm : optionals) {
                if (securityRealm != null && descriptor.clazz == securityRealm.getClass()) {
                    return securityRealm;
                }
            }
            return null;
        }

        @Override
        public SecurityRealm newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            JSONArray array = formData.getJSONArray("optional");
            DescriptorExtensionList<SecurityRealm, Descriptor<SecurityRealm>> all = SecurityRealm.all();
            optionals.clear();
            for (Object o : array) {
                JSONObject j = (JSONObject) o;
                boolean enabled = j.getBoolean("$enabled");
                if (enabled) {
                    String id = j.getString("$id");
                    j.remove("$id");
                    j.remove("$enabled");
                    Descriptor<SecurityRealm> descriptor = all.findByName(id);
                    if (descriptor != null) {
                        SecurityRealm realm = descriptor.newInstance(req, j);
                        if (realm != null) {
                            optionals.add(realm);
                        }
                    }
                }
            }
            save();
            MixingSecurityRealm securityRealm = (MixingSecurityRealm) super.newInstance(req, formData);
            securityRealm.optionals.clear();
            securityRealm.optionals.addAll(optionals);
            return securityRealm;
        }


        /**
         * @return 获取所有已经继承的认证方式类
         */
        private Map<Class, Class> getImplementedClass() {
            Map<Class, Class> impl = new HashMap<>();
            Class clazz = MixingSecurityRealm.class;
            while (clazz != SecurityRealm.class) {
                impl.put(clazz, clazz);
                clazz = clazz.getSuperclass();
            }
            return impl;
        }

        /**
         * @return 返回可选的认证方式
         */
        public List<Descriptor<SecurityRealm>> getSecurityRealmDescriptors() {
            List<Descriptor<SecurityRealm>> list = new ArrayList<>();
            Map<Class, Class> impl = getImplementedClass();
            for (Descriptor<SecurityRealm> d : SecurityRealm.all()) {
                if (!impl.containsKey(d.clazz)) {
                    list.add(d);
                }
            }
            final int size = optionals.size();
            list.sort((o1, o2) -> {
                int s1 = size, s2 = size + 1;
                for (int i = size - 1; i > -1; --i) {
                    Class clazz = optionals.get(i).getClass();
                    if (clazz == o1.clazz) {
                        s1 = i;
                    } else if (clazz == o2.clazz) {
                        s2 = i;
                    }
                }
                return s1 - s2;
            });
            return list;
        }
    }

}
