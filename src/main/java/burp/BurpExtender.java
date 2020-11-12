package burp;

import com.alibaba.cloudapi.client.constant.Constants;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.alibaba.cloudapi.client.HttpUtil;
import com.alibaba.cloudapi.client.constant.SystemHeader;


import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;


public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener, IContextMenuFactory
{
    // make sure to update version in build.gradle as well
    private static final String EXTENSION_VERSION = "0.1.0";

    private static final String BURP_SETTINGS_KEY = "JsonSettings";
    private static final String SETTING_VERSION = "ExtensionVersion";
    private static final String SETTING_LOG_LEVEL = "LogLevel";
    private static final String SETTING_CONFIG_VERSION = "SettingsVersion";

    public static final String EXTENSION_NAME = "Aliyun API Gateway Signer"; // Name in extender menu
    public static final String DISPLAY_NAME = "Aliyun API Signer"; // name for tabs, menu, and other UI components

    private static final String NO_DEFAULT_PROFILE = "        "; // ensure combobox is visible. SigProfile.profileNamePattern doesn't allow this name

    private static final String SIGNATURE_HEADERS = "x-ca-signature-headers";
    private static final String SIGNATURE_KEY = "x-ca-key";
    // define headers for internal use
    protected IExtensionHelpers helpers;
    protected IBurpExtenderCallbacks callbacks;
    private HashMap<String, String> signProfileKeyMap; // map appKey to profile
    private HashMap<String, SigProfile> signProfileMap; // map name to profile
    protected LogWriter logger = LogWriter.getLogger();

    private JLabel statusLabel;
    private JCheckBox signingEnabledCheckBox;
    private JComboBox<String> defaultProfileComboBox;
    private JComboBox<Object> logLevelComboBox;
    private JCheckBox persistProfilesCheckBox;
    private JCheckBox inScopeOnlyCheckBox;
    private JCheckBox customSignHeaderCheckBox;
    private JTextField additionalSignedHeadersField;
    private AdvancedSettingsDialog advancedSettingsDialog;

    private JTable profileTable;
    private JScrollPane outerScrollPane;

    // mimic burp colors
    protected static final Color textOrange = new Color(255, 102, 51);
    protected static final Color darkOrange = new Color(226, 73, 33);

    private static BurpExtender burpInstance;

    public static BurpExtender getBurp()
    {
        return burpInstance;
    }

    public BurpExtender() {}

    private void buildUiTab()
    {
        final Font sectionFont = new JLabel().getFont().deriveFont(Font.BOLD, 15);

        //
        // global settings, checkboxes
        //
        JPanel globalSettingsPanel = new JPanel();
        globalSettingsPanel.setLayout(new GridBagLayout());
        JLabel settingsLabel = new JLabel("Settings");
        settingsLabel.setForeground(BurpExtender.textOrange);
        settingsLabel.setFont(sectionFont);
        JPanel checkBoxPanel = new JPanel();
        signingEnabledCheckBox = new JCheckBox("Signing Enabled");
        signingEnabledCheckBox.setToolTipText("Enable SigV4 signing");
        inScopeOnlyCheckBox = new JCheckBox("In-scope Only");
        inScopeOnlyCheckBox.setToolTipText("Sign in-scope requests only");
        persistProfilesCheckBox = new JCheckBox("Persist Profiles");
        persistProfilesCheckBox.setToolTipText("Save profiles, including keys, in Burp settings store");
        customSignHeaderCheckBox = new JCheckBox("custom Signer Header");
        customSignHeaderCheckBox.setToolTipText("custom signer header,eg, x-ca-signature-headers: x-ca-key,x-ca-nonce,x-ca-signaturemethod,x-ca-stage");
        checkBoxPanel.add(signingEnabledCheckBox);
        checkBoxPanel.add(inScopeOnlyCheckBox);
        checkBoxPanel.add(persistProfilesCheckBox);
        checkBoxPanel.add(customSignHeaderCheckBox);
        JPanel otherSettingsPanel = new JPanel();
        defaultProfileComboBox = new JComboBox<>();
        logLevelComboBox = new JComboBox<>();
        otherSettingsPanel.add(new JLabel("Log Level"));
        otherSettingsPanel.add(logLevelComboBox);
        otherSettingsPanel.add(new JLabel("Default Profile"));
        otherSettingsPanel.add(defaultProfileComboBox);

        JButton advancedSettingsButton = new JButton("Advanced");
        advancedSettingsButton.addActionListener(actionEvent -> {
            advancedSettingsDialog.setVisible(true);
        });
        checkBoxPanel.add(new JSeparator(SwingConstants.VERTICAL));
        checkBoxPanel.add(advancedSettingsButton);
        advancedSettingsDialog = AdvancedSettingsDialog.get();
        advancedSettingsDialog.applyExtensionSettings(new ExtensionSettings()); // load with defaults for now

        GridBagConstraints c00 = new GridBagConstraints(); c00.anchor = GridBagConstraints.FIRST_LINE_START; c00.gridy = 0; c00.gridwidth = 2;
        GridBagConstraints c01 = new GridBagConstraints(); c01.anchor = GridBagConstraints.FIRST_LINE_START; c01.gridy = 1; c01.gridwidth = 2; c01.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c02 = new GridBagConstraints(); c02.anchor = GridBagConstraints.FIRST_LINE_START; c02.gridy = 2;
        GridBagConstraints c03 = new GridBagConstraints(); c03.anchor = GridBagConstraints.FIRST_LINE_START; c03.gridy = 3;

        globalSettingsPanel.add(settingsLabel, c00);
        globalSettingsPanel.add(new JLabel("<html>Change plugin behavior. Set <i>Default Profile</i> to force signing of all requests with the specified profile credentials."), c01);
        globalSettingsPanel.add(checkBoxPanel, c02);
        globalSettingsPanel.add(otherSettingsPanel, c03);

        //
        // status label
        //
        JPanel statusPanel = new JPanel();
        statusLabel = new JLabel();
        statusPanel.add(statusLabel);

        //
        // profiles table
        //
        JPanel profilePanel = new JPanel(new GridBagLayout());
        JLabel profileLabel = new JLabel("Aliyun API Gateway Credentials");
        profileLabel.setForeground(BurpExtender.textOrange);
        profileLabel.setFont(sectionFont);

        JButton addProfileButton = new JButton("Add");
        JButton editProfileButton = new JButton("Edit");
        JButton removeProfileButton = new JButton("Remove");
        JButton importProfileButton = new JButton("Import");
        JButton exportProfileButton = new JButton("Export");
        JPanel profileButtonPanel = new JPanel(new GridLayout(7, 1));
        profileButtonPanel.add(addProfileButton);
        profileButtonPanel.add(editProfileButton);
        profileButtonPanel.add(removeProfileButton);
        profileButtonPanel.add(importProfileButton);
        profileButtonPanel.add(exportProfileButton);

        final String[] profileColumnNames = {"Name", "APP Key", "APP Secret"};
        profileTable = new JTable(new DefaultTableModel(profileColumnNames, 0)
        {
            @Override
            public boolean isCellEditable(int row, int column)
            {
                // prevent table cells from being edited. must use dialog to edit.
                return false;
            }
        });

        JScrollPane profileScrollPane = new JScrollPane(profileTable);
        profileScrollPane.setPreferredSize(new Dimension(1000, 200));
        GridBagConstraints c000 = new GridBagConstraints(); c000.gridy = 0; c000.gridwidth = 2; c000.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c001 = new GridBagConstraints(); c001.gridy = 1; c001.gridwidth = 2; c001.anchor = GridBagConstraints.FIRST_LINE_START;
        c001.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c002 = new GridBagConstraints(); c002.gridy = 2; c002.gridx = 0; c002.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c003 = new GridBagConstraints(); c003.gridy = 2; c003.gridx = 1; c003.anchor = GridBagConstraints.FIRST_LINE_START;
        profilePanel.add(profileLabel, c000);
        profilePanel.add(new JLabel("<html>Add Aliyun API gateway credentials using your <i>AppKey</i> and <i>AppSecret</i>.</html>"), c001);
        profilePanel.add(profileButtonPanel, c002);
        profilePanel.add(profileScrollPane, c003);

        //
        // additional headers to sign
        //
        JPanel additionalSignedHeadersPanel = new JPanel(new GridBagLayout());
        JLabel additionalHeadersLabel = new JLabel("Signed Headers");
        additionalHeadersLabel.setForeground(this.textOrange);
        additionalHeadersLabel.setFont(sectionFont);
        additionalSignedHeadersField = new JTextField("", 65);
        GridBagConstraints c200 = new GridBagConstraints(); c200.gridy = 0; c200.gridwidth = 2; c200.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c201 = new GridBagConstraints(); c201.gridy = 1; c201.gridwidth = 2; c201.anchor = GridBagConstraints.FIRST_LINE_START; c201.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c202 = new GridBagConstraints(); c202.gridy = 2; c202.anchor = GridBagConstraints.FIRST_LINE_START;
        additionalSignedHeadersPanel.add(additionalHeadersLabel, c200);
        additionalSignedHeadersPanel.add(new JLabel("Specify comma-separated header names from the request to include in the signature. eg, x-ca-signature-headers: x-ca-key,x-ca-nonce,x-ca-signaturemethod,x-ca-stage"), c201);
        additionalSignedHeadersPanel.add(additionalSignedHeadersField, c202);

        //
        // put it all together
        //
        List<GridBagConstraints> sectionConstraints = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            GridBagConstraints c = new GridBagConstraints();
            c.gridy = i;
            c.gridx = 0;
            // add padding in all directions
            c.insets = new Insets(10, 10, 10, 10);
            c.anchor = GridBagConstraints.FIRST_LINE_START;
            c.weightx = 1.0;
            sectionConstraints.add(c);
        }

        JPanel outerPanel = new JPanel(new GridBagLayout());
        outerPanel.add(globalSettingsPanel, sectionConstraints.remove(0));
        GridBagConstraints c = sectionConstraints.remove(0);
        c.fill = GridBagConstraints.HORIZONTAL; // have separator span entire width of display
        outerPanel.add(new JSeparator(SwingConstants.HORIZONTAL), c);
        //outerPanel.add(statusPanel, sectionConstraints.remove(0));
        outerPanel.add(profilePanel, sectionConstraints.remove(0));
        c = sectionConstraints.remove(0);
        c.fill = GridBagConstraints.HORIZONTAL;
        outerPanel.add(new JSeparator(SwingConstants.HORIZONTAL), c);
        outerPanel.add(additionalSignedHeadersPanel, sectionConstraints.remove(0));

        // use outerOuterPanel to force components north
        JPanel outerOuterPanel = new JPanel(new BorderLayout());
        outerOuterPanel.add(outerPanel, BorderLayout.PAGE_START);
        outerScrollPane = new JScrollPane(outerOuterPanel);
        outerScrollPane.getVerticalScrollBar().setUnitIncrement(18);

        this.callbacks.customizeUiComponent(outerPanel);

        // profile button handlers
        addProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                SigProfileEditorDialog dialog = new SigProfileEditorDialog(null, "Add Profile", true, null);
                callbacks.customizeUiComponent(dialog);
                dialog.setVisible(true);
                // set first profile added as the default
                if (signProfileMap.size() == 1 && dialog.getNewProfileName() != null) {
                    setDefaultProfileName(dialog.getNewProfileName());
                }
            }
        });
        editProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                int[] rowIndeces = profileTable.getSelectedRows();
                if (rowIndeces.length == 1) {
                    DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                    final String name = (String) model.getValueAt(rowIndeces[0], 0);
                    JDialog dialog = new SigProfileEditorDialog(null, "Edit Profile", true, signProfileMap.get(name));
                    callbacks.customizeUiComponent(dialog);
                    dialog.setVisible(true);
                }
                else {
                    updateStatus("Select a single profile to edit");
                }
            }
        });
        removeProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                ArrayList<String> profileNames = new ArrayList<>();
                for (int rowIndex : profileTable.getSelectedRows()) {
                    profileNames.add((String) model.getValueAt(rowIndex, 0));
                }
                for (final String name : profileNames) {
                    deleteProfile(signProfileMap.get(name));
                }
            }
        });

        importProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                try {
                    SigProfileImportDialog importDialog = new SigProfileImportDialog(null, "Import Profiles", true);
                    callbacks.customizeUiComponent(importDialog);
                    importDialog.setVisible(true);
                }
                catch (Exception exc) {
                    logger.error("Failed to display import dialog: "+exc);
                }
            }
        });
        exportProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                JFileChooser chooser = new JFileChooser(System.getProperty("user.home"));
                chooser.setFileHidingEnabled(false);
                if (chooser.showOpenDialog(getUiComponent()) == JFileChooser.APPROVE_OPTION) {
                    final Path exportPath = Paths.get(chooser.getSelectedFile().getPath());
                    ArrayList<SigProfile> sigProfiles = new ArrayList<>();
                    for (final String name : signProfileMap.keySet()) {
                        sigProfiles.add(signProfileMap.get(name));
                    }
                    int exportCount = SigProfile.exportToFilePath(sigProfiles, exportPath);
                    final String msg = String.format("Exported %d profiles to %s", exportCount, exportPath);
                    JOptionPane.showMessageDialog(getUiComponent(), formatMessageHtml(msg));
                    logger.info(msg);
                }
            }
        });

        // log level combo box
        class LogLevelComboBoxItem
        {
            final private int logLevel;
            final private String levelName;

            public LogLevelComboBoxItem(final int logLevel)
            {
                this.logLevel = logLevel;
                this.levelName = LogWriter.levelNameFromInt(logLevel);
            }

            @Override
            public String toString()
            {
                return this.levelName;
            }
        }
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.DEBUG_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.INFO_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.ERROR_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.FATAL_LEVEL));
        this.logLevelComboBox.setSelectedIndex(logger.getLevel());

        this.logLevelComboBox.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                logger.setLevel(((LogLevelComboBoxItem) logLevelComboBox.getSelectedItem()).logLevel);
            }
        });
    }

    public boolean isSigningEnabled()
    {
        return this.signingEnabledCheckBox.isSelected();
    }
    public boolean isInScopeOnlyEnabled() { return this.inScopeOnlyCheckBox.isSelected(); }

    private void setLogLevel(final int level)
    {
        this.logger.setLevel(level);
        // logger is created before UI components are initialized.
        if (this.logLevelComboBox != null) {
            this.logLevelComboBox.setSelectedIndex(logger.getLevel());
        }
    }

    // format a message for display in a dialog. applies reasonable word-wrapping.
    public static String formatMessageHtml(final String msg) {
        return "<html><p style='width: 300px;'>" +
                StringEscapeUtils.escapeHtml4(msg) +
                "</p></html>";
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        burpInstance = this;

        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;

        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerExtensionStateListener(this);

        this.logger.configure(callbacks.getStdout(), callbacks.getStderr(), LogWriter.DEFAULT_LEVEL);
        final String setting = this.callbacks.loadExtensionSetting(SETTING_LOG_LEVEL);
        if (setting != null) {
            try {
                setLogLevel(Integer.parseInt(setting));
            } catch (NumberFormatException ignored) {
                // use default level
            }
        }

        this.signProfileKeyMap = new HashMap<>();
        this.signProfileMap = new HashMap<>();

        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                buildUiTab();
                loadExtensionSettings();
                callbacks.addSuiteTab(BurpExtender.this);
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerContextMenuFactory(BurpExtender.this);
                logger.info(String.format("Loaded %s %s", EXTENSION_NAME, EXTENSION_VERSION));
            }
        });
    }


    /*
    build Gson object for de/serialization of settings. SigCredential, SigCredentialProvider, and Path need
    to be handled as a special case since they're interfaces.
     */
    private Gson getGsonSerializer(final double settingsVersion)
    {
        return new GsonBuilder()
                .registerTypeHierarchyAdapter(Path.class, new TypeAdapter<Path>() {
                    @Override
                    public void write(JsonWriter out, Path value) throws IOException {
                        if (value == null)
                            out.nullValue();
                        else
                            out.value(value.toString());
                    }

                    @Override
                    public Path read(JsonReader in) throws IOException {
                        return Paths.get(in.nextString());
                    }
                })
                .setPrettyPrinting() // not necessary...
                .setVersion(settingsVersion)
                //.setFieldNamingPolicy(FieldNamingPolicy.UPPER_CAMEL_CASE)
                .create();
    }

    protected String exportExtensionSettingsToJson()
    {
        ExtensionSettings.ExtensionSettingsBuilder builder = ExtensionSettings.builder()
                .logLevel(this.logger.getLevel())
                .extensionVersion(EXTENSION_VERSION)
                .persistProfiles(this.persistProfilesCheckBox.isSelected())
                .extensionEnabled(this.signingEnabledCheckBox.isSelected())
                .defaultProfileName(this.getDefaultProfileName())
                .additionalSignedHeaderNames(getAdditionalSignedHeadersFromUI())
                .inScopeOnly(this.inScopeOnlyCheckBox.isSelected())
                .preserveHeaderOrder(this.advancedSettingsDialog.preserveHeaderOrderCheckBox.isSelected())
                .presignedUrlLifetimeInSeconds(this.advancedSettingsDialog.getPresignedUrlLifetimeSeconds())
                .contentMD5HeaderBehavior(this.advancedSettingsDialog.getContentMD5HeaderBehavior())
                .signingEnabledForSpider(advancedSettingsDialog.signingEnabledForSpiderCheckBox.isSelected())
                .signingEnabledForScanner(advancedSettingsDialog.signingEnabledForScannerCheckBox.isSelected())
                .signingEnabledForIntruder(advancedSettingsDialog.signingEnabledForIntruderCheckBox.isSelected())
                .signingEnabledForRepeater(advancedSettingsDialog.signingEnabledForRepeaterCheckBox.isSelected())
                .signingEnabledForSequencer(advancedSettingsDialog.signingEnabledForSequencerCheckBox.isSelected())
                .signingEnabledForExtender(advancedSettingsDialog.signingEnabledForExtenderCheckBox.isSelected());
        if (this.persistProfilesCheckBox.isSelected()) {
            builder.profiles(this.signProfileMap);
            logger.info(String.format("Saved %d profile(s)", this.signProfileMap.size()));
        }
        ExtensionSettings settings = builder.build();
        return getGsonSerializer(settings.settingsVersion()).toJson(settings);
    }

    protected void importExtensionSettingsFromJson(final String jsonString)
    {
        if (StringUtils.isEmpty(jsonString)) {
            logger.error("Invalid Json settings. Skipping import.");
            return;
        }

        double settingsVersion = 0.0;
        try {
            settingsVersion = Integer.parseInt(callbacks.loadExtensionSetting(SETTING_CONFIG_VERSION));
        } catch (NumberFormatException ignored) {
        }

        ExtensionSettings settings;
        try {
            settings = getGsonSerializer(settingsVersion).fromJson(jsonString, ExtensionSettings.class);
        } catch (JsonParseException exc) {
            logger.error("Failed to parse Json settings. Using defaults.");
            settings = ExtensionSettings.builder().build();
        }

        setLogLevel(settings.logLevel());

        // load profiles
        Map<String, SigProfile> profileMap = settings.profiles();
        for (final String name : profileMap.keySet()) {
            try {
                addProfile(profileMap.get(name));
            } catch (IllegalArgumentException | NullPointerException exc) {
                logger.error("Failed to add profile: "+name);
            }
        }

        setDefaultProfileName(settings.defaultProfileName());
        this.persistProfilesCheckBox.setSelected(settings.persistProfiles());
        this.signingEnabledCheckBox.setSelected(settings.extensionEnabled());
        this.additionalSignedHeadersField.setText(String.join(", ", settings.additionalSignedHeaderNames()));
        this.inScopeOnlyCheckBox.setSelected(settings.inScopeOnly());

        final long lifetime = settings.presignedUrlLifetimeInSeconds();
        if (lifetime < ExtensionSettings.PRESIGNED_URL_LIFETIME_MIN_SECONDS || lifetime > ExtensionSettings.PRESIGNED_URL_LIFETIME_MAX_SECONDS) {
            settings = settings.withPresignedUrlLifetimeInSeconds(ExtensionSettings.PRESIGNED_URL_LIFETIME_DEFAULT_SECONDS);
        }

        final String behavior = settings.contentMD5HeaderBehavior();
        if (!Arrays.asList(ExtensionSettings.CONTENT_MD5_REMOVE, ExtensionSettings.CONTENT_MD5_IGNORE, ExtensionSettings.CONTENT_MD5_UPDATE).contains(behavior)) {
            settings = settings.withContentMD5HeaderBehavior(ExtensionSettings.CONTENT_MD5_DEFAULT);
        }

        advancedSettingsDialog.applyExtensionSettings(settings);
    }

    private void saveExtensionSettings()
    {
        // save these with their own key since they may be required before the other settings are loaded
        this.callbacks.saveExtensionSetting(SETTING_LOG_LEVEL, Integer.toString(this.logger.getLevel()));
        this.callbacks.saveExtensionSetting(SETTING_VERSION, EXTENSION_VERSION);
        this.callbacks.saveExtensionSetting(BURP_SETTINGS_KEY, exportExtensionSettingsToJson());
    }

    private void loadExtensionSettings()
    {
        // plugin version that added the settings. in the future use this to migrate settings.
        final String pluginVersion = this.callbacks.loadExtensionSetting(SETTING_VERSION);
        if (pluginVersion != null)
            logger.info("Found settings for version "+pluginVersion);
        else
            logger.info("Found settings for version < 0.2.0");

        final String jsonSettingsString = this.callbacks.loadExtensionSetting(BURP_SETTINGS_KEY);
        if (StringUtils.isEmpty(jsonSettingsString)) {
            logger.info("No plugin settings found");
        }
        else {
            importExtensionSettingsFromJson(jsonSettingsString);
        }
    }


    @Override
    public void extensionUnloaded()
    {
        saveExtensionSettings();
        logger.info("Unloading "+EXTENSION_NAME);
    }

    @Override
    public String getTabCaption()
    {
        return DISPLAY_NAME;
    }

    @Override
    public Component getUiComponent()
    {
        return outerScrollPane;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
    {
        JMenu menu = new JMenu(DISPLAY_NAME);

        // add disable item
        JRadioButtonMenuItem item = new JRadioButtonMenuItem("<html><i>Disabled</i></html>", !isSigningEnabled());
        item.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                signingEnabledCheckBox.setSelected(false);
            }
        });
        menu.add(item);

        // insert "auto" profile option
        List<String> profileList = getSortedProfileNames();
        profileList.add(0, NO_DEFAULT_PROFILE); // no default option

        // add all profile names to menu, along with a listener to set the default profile when selected
        for (final String name : profileList) {
            item = new JRadioButtonMenuItem(name, isSigningEnabled() && name.equals(getDefaultProfileName()));
            item.addActionListener(new ActionListener()
            {
                @Override
                public void actionPerformed(ActionEvent actionEvent)
                {
                    JRadioButtonMenuItem item = (JRadioButtonMenuItem) actionEvent.getSource();
                    setDefaultProfileName(item.getText());
                    signingEnabledCheckBox.setSelected(true);
                }
            });
            menu.add(item);
        }

        List<JMenuItem> list = new ArrayList<>();
        list.add(menu);

        // add context menu items
        switch (invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();

                if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
                    JMenu addSignatureMenu = new JMenu("Add Signature");
                    for (final String name : profileList) {
                        if (name.length() == 0 || name.equals(NO_DEFAULT_PROFILE)) continue;
                        JMenuItem sigItem = new JMenuItem(name);
                        sigItem.setActionCommand(name);
                        sigItem.addActionListener(new ActionListener()
                        {
                            @Override
                            public void actionPerformed(ActionEvent actionEvent)
                            {
                                final String profileName = actionEvent.getActionCommand();
                                SigProfile profile = signProfileMap.get(profileName);
                                if (profile == null) {
                                    // this should never happen since the menu is populated with existing profile names
                                    JOptionPane.showMessageDialog(getUiComponent(), formatMessageHtml("Profile name does not exist: "+profileName));
                                    return;
                                }
                                final SigProfile profileCopy = profile; // reference copy is fine here
                                (new Thread(() -> {
                                    try {
                                        // XXX we do some work to prevent custom signed headers specified in the SigV4 UI from
                                        // showing up in the Raw message editor tab to prevent them from being duplicated when
                                        // it's signed again. consider modifying signRequest() to optionally skip adding these.
                                        final byte[] signedRequest = signRequest(messages[0], profileCopy);
                                        if (signedRequest == null || signedRequest.length == 0) {
                                            throw new NullPointerException("Request signing failed for profile: "+profileCopy.getName());
                                        }

                                        messages[0].setRequest(signedRequest);
                                    } catch (IllegalArgumentException | NullPointerException exc) {
                                        JOptionPane.showMessageDialog(getUiComponent(), formatMessageHtml("Failed to add signature: " + exc.getMessage()));
                                    }
                                })).start();
                            }
                        });
                        addSignatureMenu.add(sigItem);
                    }
                    list.add(addSignatureMenu);
                }
        }
        return list;
    }


    // display status message in UI
    private void updateStatus(final String status)
    {
        logger.debug("Set Status: " + status);
        this.statusLabel.setText(status);
    }

    private List<String> getSortedProfileNames()
    {
        // sort by name in table
        List<String> profileNames = new ArrayList<>(this.signProfileMap.keySet());
        Collections.sort(profileNames);
        return profileNames;
    }

    /*
    call this when profile list changes
    */
    private void updateAwsProfilesUI()
    {
        DefaultTableModel model = (DefaultTableModel) this.profileTable.getModel();
        model.setRowCount(0); // clear table
        final String defaultProfileName = (String) defaultProfileComboBox.getSelectedItem();
        defaultProfileComboBox.removeAllItems();
        defaultProfileComboBox.addItem(NO_DEFAULT_PROFILE);

        for (final String name : getSortedProfileNames()) {
            SigProfile profile = this.signProfileMap.get(name);
            model.addRow(new Object[]{profile.getName(), profile.getappKeyForProfileSelection(), profile.getappSecretForProfileSelection()});
            defaultProfileComboBox.addItem(name);
        }
        setDefaultProfileName(defaultProfileName);
    }

    /*
    NOTE: this will overwrite an existing profile with the same name
    */
    protected void addProfile(final SigProfile profile)
    {
        final SigProfile p1 = this.signProfileMap.get(profile.getName());
        if (p1 == null) {
            // profile name doesn't exist. make sure there is no keyId conflict with an existing profile
            if (profile.getappKeyForProfileSelection() != null) {
                String p2 = this.signProfileKeyMap.get(profile.getappKeyForProfileSelection());
                if (p2 != null) {
                    // keyId conflict. do not add profile
                    updateStatus("Profiles must have a unique appKey: "+profile.getName());
                    throw new IllegalArgumentException(String.format("Profiles must have a unique appKey: %s = %s", profile.getName(), p2));
                }
            }
        }

        this.signProfileMap.put(profile.getName(), profile);

        // refresh the keyId map
        this.signProfileKeyMap.clear();
        for (final SigProfile p : this.signProfileMap.values()) {
            if (p.getappKeyForProfileSelection() != null) {
                this.signProfileKeyMap.put(p.getappKeyForProfileSelection(), p.getName());
            }
        }

        updateAwsProfilesUI();
        if (p1 == null) {
            updateStatus("Added profile: " + profile.getName());
        }
        else {
            updateStatus("Saved profile: " + profile.getName());
        }
    }

    /*
    if newProfile is valid, delete oldProfile and add newProfile.
     */
    protected void updateProfile(final SigProfile oldProfile, final SigProfile newProfile)
    {
        if (oldProfile == null) {
            addProfile(newProfile);
            return;
        }

        // remove any profile with same name
        final SigProfile p1 = this.signProfileMap.get(oldProfile.getName());
        if (p1 == null) {
            updateStatus("Update profile failed. Old profile doesn't exist.");
            throw new IllegalArgumentException("Update profile failed. Old profile doesn't exist.");
        }

        // if we are updating the default profile, ensure it remains the default
        final boolean defaultProfileUpdated = getDefaultProfileName().equals(oldProfile.getName());

        deleteProfile(oldProfile);
        try {
            addProfile(newProfile);
            if (defaultProfileUpdated) {
                setDefaultProfileName(newProfile.getName());
            }
        } catch (IllegalArgumentException exc) {
            addProfile(oldProfile); // oops. add old profile back
            throw exc;
        }
    }

    private void deleteProfile(SigProfile profile)
    {
        if (this.signProfileMap.containsKey(profile.getName())) {
            this.signProfileMap.remove(profile.getName());
            updateStatus(String.format("Deleted profile '%s'", profile.getName()));
        }
        if (profile.getappKeyForProfileSelection() != null) {
            this.signProfileKeyMap.remove(profile.getappKeyForProfileSelection());
        }
        updateAwsProfilesUI();
    }

    public boolean isAPIGatewayRequest(final  IHttpRequestResponse messageInfo)
    {
        if(getHeaderValueOf(true, messageInfo, SIGNATURE_HEADERS) == null) {
            return false;
        }
        else{
            return true;
        }
    }


    private String getDefaultProfileName()
    {
        String defaultProfileName = (String) this.defaultProfileComboBox.getSelectedItem();
        if (defaultProfileName == null) {
            defaultProfileName = NO_DEFAULT_PROFILE;
        }
        return defaultProfileName;
    }

    /*
    Note that no check is done on profile name. It is assumed values come from SigProfile and are validated there.
     */
    private void setDefaultProfileName(final String defaultProfileName)
    {
        if (defaultProfileName != null) {
            for (int i = 0; i < this.defaultProfileComboBox.getItemCount(); i++) {
                if (this.defaultProfileComboBox.getItemAt(i).equals(defaultProfileName)) {
                    this.defaultProfileComboBox.setSelectedIndex(i);
                    //updateStatus("Default profile changed.");
                    return;
                }
            }
        }
        // possible if persistProfiles was set to false and default profile was not saved
    }

    private List<String> getAdditionalSignedHeadersFromUI()
    {
        try {
            String[] signHeaders = additionalSignedHeadersField.getText().split(": ")[1].split(",");
            return Arrays.asList(signHeaders);
        }
        catch(Exception e) {
            logger.error(e.toString());
            logger.error("Sigature header string format error, using format like: x-ca-signature-headers: x-ca-key, X-Ca-Nonce");
        }
    }




    public SigProfile getSigningProfile(IHttpRequestResponse messageInfo)
    {
        String appKey = getHeaderHashMap(true, messageInfo).get(SIGNATURE_KEY);
        String name = this.signProfileKeyMap.get(appKey);
        SigProfile signingProfile = this.signProfileMap.get(name);
        return signingProfile;
    }


    public static Map<String, String> getQueryMap(String query) {
        String[] params = query.split("&");
        Map<String, String> map = new HashMap<String, String>();

        for (String param : params) {
            String name = param.split("=")[0];
            String value = param.split("=")[1];
            map.put(name, value);
        }
        return map;
    }

    public byte[] getBody(boolean isRequest,byte[] requestOrResponse) {
        if (requestOrResponse == null){
            return null;
        }
        int bodyOffset = -1;
        if(isRequest) {
            IRequestInfo analyzeRequest = helpers.analyzeRequest(requestOrResponse);
            bodyOffset = analyzeRequest.getBodyOffset();
        }else {
            IResponseInfo analyzeResponse = helpers.analyzeResponse(requestOrResponse);
            bodyOffset = analyzeResponse.getBodyOffset();
        }
        byte[] byte_body = Arrays.copyOfRange(requestOrResponse, bodyOffset, requestOrResponse.length);//not length-1
        //String body = new String(byte_body); //byte[] to String
        return byte_body;
    }

    public String getHeaderValueOf(boolean messageIsRequest,IHttpRequestResponse messageInfo, String headerName) {
        final String Header_Spliter = ": ";
        List<String> headers=null;
        if(messageIsRequest) {
            if (messageInfo.getRequest() == null) {
                return null;
            }
            IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
            headers = analyzeRequest.getHeaders();
        }else {
            if (messageInfo.getResponse() == null) {
                return null;
            }
            IResponseInfo analyzeResponse = helpers.analyzeResponse(messageInfo.getResponse());
            headers = analyzeResponse.getHeaders();
        }


        headerName = headerName.toLowerCase().replace(":", "");
        for (String header : headers) {
            if (header.toLowerCase().startsWith(headerName)) {
                return header.split(Header_Spliter, 2)[1];
            }
        }
        return null;
    }

    public HashMap<String,String> getHeaderHashMap(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
        final String Header_Spliter = ": ";
        List<String> headers=null;
        HashMap<String,String> result = new HashMap<String, String>();
        //if (headers.size() <=0) return result;
        if(messageIsRequest) {
            IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
            headers = analyzeRequest.getHeaders();
        }else {
            IResponseInfo analyzeResponse = helpers.analyzeResponse(messageInfo.getResponse());
            headers = analyzeResponse.getHeaders();
        }

        for (String header : headers) {
            if(header.contains(Header_Spliter)) {//to void trigger the Exception
                try {
                    String headerName = header.split(Header_Spliter, 0)[0];
                    String headerValue = header.split(Header_Spliter, 0)[1];
                    //POST /login.pub HTTP/1.1  the first line of header will tirgger error here
                    result.put(headerName, headerValue);
                } catch (Exception e) {
                    //e.printStackTrace();
                }
            }
        }

        return result;
    }

    public static Map<String, String> splitQuery(URL url) throws UnsupportedEncodingException {
        Map<String, String> query_pairs = new LinkedHashMap<String, String>();
        String query = url.getQuery();
        if (query == null){
            return null;
        }
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }
    public byte[] signRequest(IHttpRequestResponse messageInfo, final SigProfile signingProfile) {
        final String lineOne =  helpers.analyzeRequest(messageInfo).getHeaders().get(0);
        HashMap<String,String> originalHeader  = getHeaderHashMap(true, messageInfo);
        URL fullUrl = helpers.analyzeRequest(messageInfo).getUrl();
        String reqMethod = helpers.analyzeRequest(messageInfo).getMethod();
        Map<String, String> reqParams = new HashMap<>();
        try{
            reqParams = splitQuery(fullUrl);
        }catch (UnsupportedEncodingException e){
            logger.error(e.toString());
            return null;
        }

        String[] signHeaders = originalHeader.get(SIGNATURE_HEADERS).split(",");


        String reqHost = fullUrl.getHost();
        String reqPath = fullUrl.getPath();

        List<String> finalHeaders = new ArrayList<>();


        String appSecret = signingProfile.getappSecret();
        String appKey = signingProfile.getappKey();


        final byte[] body = getBody(true, messageInfo.getRequest());

        logger.debug("\n=======ORIGINAL REQUEST HEADER==========\n"+originalHeader.toString());
        logger.debug("\n=======ORIGINAL REQUEST url params ==========\n");
        logger.debug("\n=======ORIGINAL REQUEST host, path ==========\n"+reqHost + "\n" + reqPath+ "\n" +  appSecret);


        //logger.debug(String.format("appSecret: %s,",appSecret));
        if(reqMethod == "GET") {
            finalHeaders = HttpUtil.httpGet(appKey, appSecret, signHeaders, reqHost, reqPath, reqParams, originalHeader);
        }
        else {
            if (reqMethod == "POST") {
                for (String k : originalHeader.keySet()) {
                    if (k.toLowerCase() == "content-type") {
                        if (originalHeader.get(k).toLowerCase().contains("form")) {
                            HashMap<String, String> form = null;
                            finalHeaders = HttpUtil.httpPostForm(appKey, appSecret, signHeaders, reqHost, reqPath, reqParams, form, originalHeader);
                        }
                    }
                }
            } else {
                finalHeaders = HttpUtil.httpPostBytes(appKey, appSecret, signHeaders, reqHost, reqPath, reqParams, body, originalHeader);
            }
        }
        logger.debug("\n======= buildHttpRequest ==========\n"+finalHeaders.toString());






        finalHeaders.add(0, lineOne);



        final byte[] requestBytes = helpers.buildHttpMessage(finalHeaders, body);
        logger.debug("=======FINAL REQUEST============="+helpers.bytesToString(requestBytes));
        logger.debug("=======END REQUEST=============");
        return requestBytes;
    }

    private boolean isSigningEnabledForTool(final int toolFlag)
    {
        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                return advancedSettingsDialog.signingEnabledForProxyCheckbox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SPIDER:
                return advancedSettingsDialog.signingEnabledForSpiderCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return advancedSettingsDialog.signingEnabledForScannerCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return advancedSettingsDialog.signingEnabledForIntruderCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return advancedSettingsDialog.signingEnabledForRepeaterCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                return advancedSettingsDialog.signingEnabledForSequencerCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                return advancedSettingsDialog.signingEnabledForExtenderCheckBox.isSelected();
            default:
                return false;
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        IRequestInfo request = null;
        if (!messageIsRequest){
            return;
        }

        if (signingEnabledCheckBox.isSelected() && isSigningEnabledForTool(toolFlag)) {
            if (request == null) {
                request = helpers.analyzeRequest(messageInfo);
            }

            // check request scope
            if (this.inScopeOnlyCheckBox.isSelected() && !this.callbacks.isInScope(request.getUrl())) {
                logger.debug("Skipping out of scope request: " + request.getUrl());
                return;
            }

            if (isAPIGatewayRequest(messageInfo)) {
                final SigProfile signingProfile = getSigningProfile(messageInfo);

                if (signingProfile == null) {
                    logger.error("Failed to get signing profile");
                    return;
                }

                final byte[] requestBytes = signRequest(messageInfo,  signingProfile);
                if (requestBytes != null) {
                    messageInfo.setRequest(requestBytes);
                    messageInfo.setComment(DISPLAY_NAME+" "+signingProfile.getName());
                }
                else {
                    callbacks.issueAlert(String.format("Failed to sign with profile \"%s\". See Extender log for details.", signingProfile.getName()));
                }
            }
        }
    }

}

