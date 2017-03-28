package com.vaadin.demo.ui;

import com.vaadin.data.BeanBinder;
import com.vaadin.data.BinderValidationStatus;
import com.vaadin.demo.entities.Gender;
import com.vaadin.demo.entities.Patient;
import com.vaadin.demo.repositories.PatientRepository;
import com.vaadin.server.FontAwesome;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.UIScope;
import com.vaadin.ui.*;
import com.vaadin.ui.themes.ValoTheme;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;

import java.time.LocalDate;
import java.util.Date;

@SpringComponent
@UIScope
public class PatientForm extends SubView {

    @Autowired
    PatientRepository repo;

    @Autowired
    @Lazy
    PatientDetails patientDetails;

    @Autowired
    @Lazy
    PatientView patientView;

    private NativeSelect<String> title = new NativeSelect<>("Title");
    private TextField firstName = new TextField("First name");
    private TextField middleName = new TextField("Middle name");
    private TextField lastName = new TextField("Last name");
    private NativeSelect<String> greeting = new NativeSelect<>("Greeting");
    private NativeSelect<Gender> gender = new NativeSelect<>("Gender");
    private DateField birthDate = new DateField("Date of birth");
    private TextField ssn = new TextField("SSN");
    private TextField medicalRecord = new TextField("Patient ID");

    private Button save, cancel, delete, secondaryCancel;

    BeanBinder<Patient> bb = new BeanBinder<>(Patient.class);

    boolean validating = false;

    public PatientForm() {
        setupButtons();

        populateSelects();

        bb.forField(firstName)
                .withNullRepresentation("")//.setRequired("ÖÖÖ let me have this message from JSR 303")
                .bind("firstName");

        bb.forField(birthDate).withConverter(localDate -> new Date(), date -> LocalDate.now()).bind("birthDate");

        bb.forField(medicalRecord).withConverter(v -> v == null || v.isEmpty() ? null : Long.valueOf(v), v -> v == null ? "" : Long.toString(v)).bind("medicalRecord");

        bb.bind(gender, "gender");

        bb.bindInstanceFields(this);

//        bb.setValidationStatusHandler(e -> {
//            save.setEnabled(bb.validate().isOk());
//        });
        bb.addStatusChangeListener(e -> {
            if (validating) {
                validating = false;
            } else {
                validating = true;
                save.setEnabled(bb.validate().isOk());//!e.hasValidationErrors());//bb.validate().isOk());
            }
//            Notification.show("Contains errors:" + e.hasValidationErrors(), Notification.Type.TRAY_NOTIFICATION);
        });

        addTab(buildLayouts());

    }

    private void setupButtons() {
        save = new Button("Save");
        save.addStyleName(ValoTheme.BUTTON_BORDERLESS);
        save.addStyleName("addButton");
        save.addStyleName("uppercase");
        save.addClickListener(e -> {
            BinderValidationStatus<Patient> validate = bb.validate();
            if (validate.isOk()) {
                repo.save(bb.getBean());
                close();
                // For better separation of concern, one should consider using
                // events to communicate between ui components
                patientDetails.showPatient(bb.getBean());
                patientView.listPatients();
            }
        });

        cancel = new Button("Cancel");
        cancel.addStyleName(ValoTheme.BUTTON_BORDERLESS);
        cancel.addStyleName("uppercase");
        cancel.addClickListener(e -> {
            if(bb.getBean().isPersistent()){
                close();
            }else {
                ((VaadinUI) getUI()).closeAllSubViews();
            }
        });

        delete = new Button("Delete", e -> deletePatient(bb.getBean()));
        delete.addStyleName(ValoTheme.BUTTON_BORDERLESS);
        delete.addStyleName(ValoTheme.BUTTON_DANGER);
        delete.addStyleName("uppercase");

        secondaryCancel = new Button(FontAwesome.CLOSE); // Use the Close (alias)
        secondaryCancel.addClickListener(e -> close());
        secondaryCancel.addStyleName(ValoTheme.BUTTON_BORDERLESS);
        setTopRightComponent(secondaryCancel);
    }

    private Layout buildLayouts() {
        CssLayout layout = new CssLayout();
        layout.setCaption("Editing Profile");
        layout.setSizeFull();
        layout.addStyleName("content-layout");

        FormLayout formlayout = new FormLayout(title, firstName, middleName, lastName, new Label(), gender, birthDate, ssn, medicalRecord);
//        formlayout.setMargin(true);
        formlayout.addStyleName("data-edit-layout");

        final HorizontalLayout buttonLayout = new HorizontalLayout(save, cancel, delete);
        buttonLayout.setSpacing(true);
        buttonLayout.addStyleName("buttons");

        layout.addComponent(formlayout);
        layout.addComponent(buttonLayout);

        return layout;
    }

    private void populateSelects() {
        gender.setItems(Gender.values());
        title.setItems("Miss", "Ms", "Mrs", "Mr");
    }

    void editPatient(Patient p) {
        if (p.isPersistent()) {
            p = repo.findOne(p.getId());
        }

        greeting.setItems(p.getFirstName(), p.getMiddleName());
        medicalRecord.setReadOnly(p.getMedicalRecord() != null);

        // This will skip initial call to is valid so we don't
        // get null exceptions etc. for a new Patient.
        validating = true;
        bb.setBean(p);

        save.setEnabled(false);

        show();
    }

    @Override
    public void close() {
        ((VaadinUI) getUI()).closeSubView(this, false);
    }

    @Override
    public void repaint() {
        // NOOP
    }

    private void deletePatient(Patient patient) {

        Window window = new Window();
        window.setCaption("Are you sure?");
        window.setClosable(false);
        window.setResizable(false);
        window.setModal(true);
        Label label = new Label("You are about to delete patient details of " + patient + ".");

        Button delete = new Button("Delete");
        delete.setStyleName(ValoTheme.BUTTON_DANGER);
        delete.addClickListener(e -> {
            repo.delete(patient);
            window.close();
            ((VaadinUI) getUI()).closeAllSubViews();
            // For better separation of concern, one should consider using
            // events to communicate between ui components
            patientView.listPatients();
        });

        Button cancel = new Button("Cancel");
        cancel.addClickListener(e -> {
            window.close();
        });
        HorizontalLayout actions = new HorizontalLayout(cancel, delete);
        actions.setSpacing(true);

        VerticalLayout layout = new VerticalLayout(label, actions);
        layout.setMargin(true);
        layout.setSpacing(true);

        window.setContent(layout);

        getUI().addWindow(window);
    }

}
