package burp;

import burp.error.SigCredentialProviderException;
import org.apache.commons.lang3.StringUtils;

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
    // accessKeyId is used to uniquely identify this profile for signing
    private String accessKeyId;
    private String secretKey;
/*
    private HashMap<String, SigCredentialProvider> credentialProviders;
    private HashMap<String, Integer> credentialProvidersPriority;*/

    // see https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html
    public static final Pattern profileNamePattern = Pattern.compile("^[\\w+=,.@-]{1,64}$");
    public static final Pattern accessKeyIdPattern = Pattern.compile("^[\\w]{5,20}$");
    public static final Pattern secretKeyPattern = Pattern.compile("^[a-zA-Z0-9/+]{1,128}$"); // base64 characters. not sure on length

    public String getName() { return this.name; }


    // NOTE that this value is used for matching incoming requests only and DOES NOT represent the accessKeyId
    // used to sign the request
    public String getAccessKeyId() { return this.accessKeyId; }
    public String getSecretKey() { return this.secretKey; }
    /*
    get the signature accessKeyId that should be used for selecting this profile
     */
    public String getAccessKeyIdForProfileSelection()
    {
        if (getAccessKeyId() != null) {
            return getAccessKeyId();
        }
        return null;
    }

    public String getSecretKeyForProfileSelection()
    {
        if (getSecretKey() != null) {
            return getSecretKey();
        }
        return null;
    }
    private void setName(final String name) {
        if (profileNamePattern.matcher(name).matches())
            this.name = name;
        else
            throw new IllegalArgumentException("Profile name must match pattern "+profileNamePattern.pattern());
    }

    private void setAccessKeyId(final String accessKeyId) {
        if (accessKeyIdPattern.matcher(accessKeyId).matches())
            this.accessKeyId = accessKeyId;
        else
            throw new IllegalArgumentException("Profile accessKeyId must match pattern " + accessKeyIdPattern.pattern());
    }

    private void setSecretKey(final String secretKey) {
        if (secretKeyPattern.matcher(secretKey).matches())
            this.secretKey = secretKey;
        else
            throw new IllegalArgumentException("Profile secret key must match pattern " + secretKeyPattern.pattern());
    }
/*
    private void setCredentialProvider(final SigCredentialProvider provider, final int priority) {
        if (provider == null) {
            throw new IllegalArgumentException("Cannot set a null credential provider");
        }
        this.credentialProviders.put(provider.getName(), provider);
        this.credentialProvidersPriority.put(provider.getName(), priority);
    }*/

    public static class Builder {
        private SigProfile profile;
        public Builder(final String name) {
            this.profile = new SigProfile(name);
        }
        public Builder(final SigProfile profile) {
            this.profile = profile.clone();
        }
        public Builder withAccessKeyId(final String accessKeyId) {
            this.profile.setAccessKeyId(accessKeyId);
            return this;
        }
        public Builder withAccessKeySecretKey(final String accessKeyId, final String secretKey) {
            this.profile.setAccessKeyId(accessKeyId);
            this.profile.setSecretKey(secretKey);
            return this;
        }
/*        public Builder withCredentialProvider(final SigCredentialProvider provider, final int priority) {
            // should only have 1 of each type: permanent/static, assumeRole, etc
            this.profile.setCredentialProvider(provider, priority);
            return this;
        }
        */
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
        this.accessKeyId = null;
        this.secretKey = null;
        /*
        this.credentialProviders = new HashMap<>();
        this.credentialProvidersPriority = new HashMap<>();*/
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

    // refs: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
    //       https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html
    //
    // Read profiles from an aws cli credential file. Additional properties may be read from the config
    // file where profile names must be specified with a "profile " prefix.
    public static List<SigProfile> fromCredentialPath(final Path path)
    {
        // parse credential file
        List<SigProfile> profileList = new ArrayList<>();
        Map<String, Map<String, String>> credentials = ConfigParser.parse(path);

        // get aws cli config file if it exists.
        Map<String, Map<String, String>> config = ConfigParser.parse(getCliConfigPath());

        // build profile list. settings in credentials file will take precedence over the config file.
        for (final String name : credentials.keySet()) {
            // combine profile settings from credential and config file into a single map. add credentials last
            // to overwrite duplicate settings from the config map. we want to prioritize values in the credential file
            Map<String, String> section = new HashMap<>();
            section.putAll(config.getOrDefault("profile "+name, new HashMap<>()));
            section.putAll(credentials.getOrDefault(name, new HashMap<>()));

            if ((section.containsKey("aws_access_key_id") && section.containsKey("aws_secret_access_key")) || section.containsKey("source_profile")) {
/*                final String region = section.getOrDefault("region", "");*/
                String accessKeyId = section.getOrDefault("aws_access_key_id", null);
                String secretAccessKey = section.getOrDefault("aws_secret_access_key", null);
/*
                String sessionToken = section.getOrDefault("aws_session_token", null);
*/

                // if source_profile exists, check that profile for creds.
                if (section.containsKey("source_profile")) {
                    final String source = section.get("source_profile");
                    Map<String, String> sourceSection = new HashMap<>();
                    sourceSection.putAll(config.getOrDefault("profile "+source, new HashMap<>()));
                    sourceSection.putAll(credentials.getOrDefault(source, new HashMap<>()));
                    if (sourceSection.containsKey("aws_access_key_id") && sourceSection.containsKey("aws_secret_access_key")) {
                        accessKeyId = sourceSection.get("aws_access_key_id");
                        secretAccessKey = sourceSection.get("aws_secret_access_key");
/*
                        sessionToken = sourceSection.getOrDefault("aws_session_token", null);
*/
                    }
                    else {
                        logger.error(String.format("Profile [%s] refers to source_profile [%s] which does not contain credentials.", name, source));
                        continue;
                    }
                }

                SigProfile.Builder newProfileBuilder = new SigProfile.Builder(name).withAccessKeySecretKey(accessKeyId,secretAccessKey);
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
                export += this.getExportString();
            } catch (SigCredentialProviderException exc) {
                logger.error("Failed to export credential: "+export);
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
        return String.format("name = '%s', keyId = '%s'", name, accessKeyId);
    }
}
