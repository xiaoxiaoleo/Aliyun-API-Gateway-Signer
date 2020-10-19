package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.time.Instant;

public class SigProfileEditorDialog extends JDialog
{
    static final Color disabledColor = new Color(161, 161, 161);
    private static final BurpExtender burp = BurpExtender.getBurp();

    protected JTextField nameTextField;
    protected JButton okButton;
    protected JPanel providerPanel;

    private JTextField accessKeyTextField;
    protected JTextField secretKeyTextField;
    private JLabel statusLabel;
    private String newProfileName = null;

    // allow creator of dialog to get the profile that was created
    public String getNewProfileName() { return newProfileName; }

    private static GridBagConstraints newConstraint(int gridx, int gridy, int gridwidth, int gridheight)
    {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = gridy;
        c.gridx = gridx;
        c.gridwidth = gridwidth;
        c.gridheight = gridheight;
        return c;
    }

    private static GridBagConstraints newConstraint(int gridx, int gridy, int anchor)
    {
        GridBagConstraints c = newConstraint(gridx, gridy, 1, 1);
        c.anchor = anchor;
        return c;
    }

    private static GridBagConstraints newConstraint(int gridx, int gridy)
    {
        return newConstraint(gridx, gridy, 1, 1);
    }

    /*
    return a dialog with a form for editing profiles. optional profile param can be used to populate the form.
    set profile to null for a create form.
     */
    public SigProfileEditorDialog(Frame owner, String title, boolean modal, SigProfile profile)
    {
        super(owner, title, modal);
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel outerPanel = new JPanel(new GridBagLayout());
        final int TEXT_FIELD_WIDTH = 40;
        int outerPanelY = 0;
        int providerPanelY = 0;

        // panel for required fields
        JPanel basicPanel = new JPanel(new GridBagLayout());
        basicPanel.setBorder(new TitledBorder("Profile"));
        basicPanel.add(new JLabel("Name"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.nameTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH, "Required");
        basicPanel.add(nameTextField, newConstraint(1, 0));
        outerPanel.add(basicPanel, newConstraint(0, outerPanelY++, GridBagConstraints.LINE_START));

        providerPanel = new JPanel(new GridBagLayout());

        // panel for static credentials
        JPanel staticCredentialsPanel = new JPanel(new GridBagLayout());
        staticCredentialsPanel.setBorder(new TitledBorder("Credentials"));

        staticCredentialsPanel.add(new JLabel("AccessKey"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.accessKeyTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Required");
        staticCredentialsPanel.add(accessKeyTextField, newConstraint(1, 0));
        staticCredentialsPanel.add(new JLabel("SecretKey"), newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.secretKeyTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Required");
        staticCredentialsPanel.add(secretKeyTextField, newConstraint(1, 1));
        providerPanel.add(staticCredentialsPanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));


        outerPanel.add(providerPanel, newConstraint(0, outerPanelY++, GridBagConstraints.LINE_START));
        statusLabel = new JLabel("<html><i>Ok to submit</i></html>");
        statusLabel.setForeground(BurpExtender.textOrange);
        okButton = new JButton("Ok");
        JButton cancelButton = new JButton("Cancel");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        outerPanel.add(statusLabel, newConstraint(0, outerPanelY++, 2, 1));
        outerPanel.add(buttonPanel, newConstraint(0, outerPanelY++, 2, 1));

        cancelButton.addActionListener(actionEvent -> {
            setVisible(false);
            dispose();
        });
        okButton.addActionListener(actionEvent -> {
            //SigAssumeRoleCredentialProvider assumeRole = null;
            final String accessKey = accessKeyTextField.getText();
            final String secretKey = secretKeyTextField.getText();

            try {
                SigProfile.Builder newProfileBuilder = new SigProfile.Builder(nameTextField.getText());

                // if any cred fields are specified, attempt to use them.
                if (!accessKey.equals("") || !secretKey.equals("") ) {
                    newProfileBuilder.withAccessKeySecretKey(accessKeyTextField.getText(), secretKeyTextField.getText());
                }

                final SigProfile newProfile = newProfileBuilder.build();
                burp.updateProfile(profile, newProfile);
                newProfileName = newProfile.getName();
                setVisible(false);
                dispose();
            } catch (IllegalArgumentException exc) {
                setStatusLabel("Invalid settings: " + exc.getMessage());
            }
        });

        // populate fields with existing profile for an "edit" dialog.
        staticCredentialsPanel.setVisible(true);
        applyProfile(profile);

        add(outerPanel);
        pack();
        // setting to burp.getUiComponent() is not sufficient for dialogs popped outside the SigV4 tab.
        setLocationRelativeTo(SwingUtilities.getWindowAncestor(burp.getUiComponent()));
    }

    protected void setStatusLabel(final String message)
    {
        statusLabel.setText(BurpExtender.formatMessageHtml(message));
        pack();
    }

    protected void applyProfile(final SigProfile profile)
    {
        if (profile != null) {
            nameTextField.setText(profile.getName());
            accessKeyTextField.setText(profile.getAccessKey());
            secretKeyTextField.setText(profile.getSecretKey());
        }
    }
}


/*
This class implements a JTextField with "Optional" hint text when no user input is present.
 */
class JTextFieldHint extends JTextField implements FocusListener
{
    private Font defaultFont;
    private Color defaultForegroundColor;
    final private Color hintForegroundColor = SigProfileEditorDialog.disabledColor;;
    private String hintText;

    public JTextFieldHint(String content, int width, String hintText) {
        // set text below to prevent NullPointerException
        super(width);
        this.hintText = hintText;
        init();
        setText(content);
    }

    void init() {
        defaultFont = getFont();
        addFocusListener(this);
        defaultForegroundColor = getForeground();
        if (super.getText().equals("")) {
            displayHintText();
        }
    }

    @Override
    public String getText() {
        // make sure we don't return "Optional" when these fields are saved
        if (getFont().isItalic()) {
            return "";
        }
        return super.getText();
    }

    @Override
    public void setText(final String text) {
        if (!text.equals("")) {
            setUserText(text);
        }
        else {
            displayHintText();
        }
    }

    protected void setHintText(final String text) {
        this.hintText = text;
        if (getFont().isItalic()) {
            displayHintText();
        }
    }

    protected void displayHintText() {
        setFont(new Font(defaultFont.getFamily(), Font.ITALIC, defaultFont.getSize()));
        setForeground(hintForegroundColor);
        super.setText(hintText);
    }

    private void setUserText(final String text) {
        setFont(defaultFont);
        setForeground(defaultForegroundColor);
        super.setText(text);
    }

    @Override
    public void focusGained(FocusEvent focusEvent) {
        if (getFont().isItalic()) {
            setUserText("");
        }
    }

    @Override
    public void focusLost(FocusEvent focusEvent) {
        if (super.getText().equals("")) {
            displayHintText();
        }
    }
}

