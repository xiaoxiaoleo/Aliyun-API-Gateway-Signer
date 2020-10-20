package burp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/*
Class represents a credential set for AWS services. Provides functionality
to import credentials from environment vars or a credential file.
*/
public class SigProfile implements Cloneable
{
    public static final int DEFAULT_STATIC_PRIORITY = 100;

    private static final transient LogWriter logger = LogWriter.getLogger();

    private String name;
    // appKey is used to uniquely identify this profile for signing
    private String appKey;
    private String appSecret;

    //
    public static final Pattern profileNamePattern = Pattern.compile("^[\\w+=,.@-]{1,64}$");
    public static final Pattern appKeyPattern = Pattern.compile("^[\\w]{5,20}$");
    public static final Pattern appSecretPattern = Pattern.compile("^[a-zA-Z0-9/+]{1,128}$"); // base64 characters. not sure on length

    public String getName() { return this.name; }


    // NOTE that this value is used for matching incoming requests only and DOES NOT represent the appKey
    // used to sign the request
    public String getappKey() { return this.appKey; }
    public String getappSecret() { return this.appSecret; }
    /*
    get the signature appKey that should be used for selecting this profile
     */
    public String getappKeyForProfileSelection()
    {
        if (getappKey() != null) {
            return getappKey();
        }
        return null;
    }

    public String getappSecretForProfileSelection()
    {
        if (getappSecret() != null) {
            return getappSecret();
        }
        return null;
    }
    private void setName(final String name) {
        if (profileNamePattern.matcher(name).matches())
            this.name = name;
        else
            throw new IllegalArgumentException("Profile name must match pattern "+profileNamePattern.pattern());
    }

    private void setappKey(final String appKey) {
        if (appKeyPattern.matcher(appKey).matches())
            this.appKey = appKey;
        else
            throw new IllegalArgumentException("Profile appKey must match pattern " + appKeyPattern.pattern());
    }

    private void setappSecret(final String appSecret) {
        if (appSecretPattern.matcher(appSecret).matches())
            this.appSecret = appSecret;
        else
            throw new IllegalArgumentException("Profile secret key must match pattern " + appSecretPattern.pattern());
    }

    public static class Builder {
        private SigProfile profile;
        public Builder(final String name) {
            this.profile = new SigProfile(name);
        }
        public Builder(final SigProfile profile) {
            this.profile = profile.clone();
        }
        public Builder withappKey(final String appKey) {
            this.profile.setappKey(appKey);
            return this;
        }
        public Builder withappKeyappSecret(final String appKey, final String appSecret) {
            this.profile.setappKey(appKey);
            this.profile.setappSecret(appSecret);
            return this;
        }
        public SigProfile build() {
            return this.profile;
        }
    }

    public SigProfile clone() {
        SigProfile.Builder builder = new SigProfile.Builder(this.name);
        return builder.build();
    }

    private SigProfile() {};

    private SigProfile(final String name)
    {
        setName(name);
        this.appKey = null;
        this.appSecret = null;
    }

    private static Path getCliConfigPath()
    {
        Path configPath;
        final String envFile = System.getenv("AWS_CONFIG_FILE");
        if (envFile != null && Files.exists(Paths.get(envFile))) {
            configPath = Paths.get(envFile);
        }
        else {
            configPath = Paths.get(System.getProperty("user.home"), ".aws", "config");
        }
        return configPath;
    }
 
    // Read profiles from an alibaba API gateway credential file. Additional properties may be read from the config
    // file where profile names must be specified with a "profile " prefix.
    public static List<SigProfile> fromCredentialPath(final Path path)
    {
        // parse credential file
        List<SigProfile> profileList = new ArrayList<>();
        Map<String, Map<String, String>> credentials = ConfigParser.parse(path);

        // get alibaba API gateway config file if it exists.
        Map<String, Map<String, String>> config = ConfigParser.parse(getCliConfigPath());

        // build profile list. settings in credentials file will take precedence over the config file.
        for (final String name : credentials.keySet()) {
            // combine profile settings from credential and config file into a single map. add credentials last
            // to overwrite duplicate settings from the config map. we want to prioritize values in the credential file
            Map<String, String> section = new HashMap<>();
            section.putAll(config.getOrDefault("profile "+name, new HashMap<>()));
            section.putAll(credentials.getOrDefault(name, new HashMap<>()));

            if ((section.containsKey("AppKey") && section.containsKey("appSecret")) || section.containsKey("source_profile")) {
                String appKey = section.getOrDefault("AppKey", null);
                String appSecret = section.getOrDefault("appSecret", null);
                // if source_profile exists, check that profile for creds.
                if (section.containsKey("source_profile")) {
                    final String source = section.get("source_profile");
                    Map<String, String> sourceSection = new HashMap<>();
                    sourceSection.putAll(config.getOrDefault("profile "+source, new HashMap<>()));
                    sourceSection.putAll(credentials.getOrDefault(source, new HashMap<>()));
                    if (sourceSection.containsKey("AppKey") && sourceSection.containsKey("appSecret")) {
                        appKey = sourceSection.get("AppKey");
                        appSecret = sourceSection.get("appSecret");

                    }
                    else {
                        logger.error(String.format("Profile [%s] refers to source_profile [%s] which does not contain credentials.", name, source));
                        continue;
                    }
                }

                SigProfile.Builder newProfileBuilder = new SigProfile.Builder(name).withappKeyappSecret(appKey,appSecret);
                profileList.add(newProfileBuilder.build());
            }
        }
        return profileList;
    }

    private String formatLine(final String fmt, final Object ... params) {
        return String.format(fmt + System.lineSeparator(), params);
    }

    private String getExportString()
    {
        String export = "";
        if (true) {
            export += formatLine("[%s]", this.name);
            try {
                export += this.toString();
            }
            catch(Exception e){
                logger.error("Failed to export credential: "+e.toString());
                return "";
            }
        }
        return export;
    }

    public static int exportToFilePath(final List<SigProfile> sigProfiles, final Path exportPath)
    {
        List<String> exportLines = new ArrayList<>();
        for (final SigProfile profile : sigProfiles) {
            final String export = profile.getExportString();
            if (!export.equals("")) {
                exportLines.add(export);
            }
        }
        if (exportLines.size() > 0) {
            try {
                Files.write(exportPath, exportLines, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
            }
            catch (IOException exc) {
                exportLines.clear();
            }
        }
        return exportLines.size();
    }


    @Override
    public String toString() {
        return String.format("AppKey = %s \nappSecret=%s\n", appKey, appSecret);
    }
}
