package com.vaadin.demo.ui.views.patients.profile;

import com.vaadin.data.BeanValidationBinder;
import com.vaadin.data.ValidationException;
import com.vaadin.demo.entities.Doctor;
import com.vaadin.demo.entities.Gender;
import com.vaadin.demo.entities.Patient;
import com.vaadin.demo.repositories.DoctorRepository;
import com.vaadin.demo.ui.converters.DateConverter;
import com.vaadin.demo.ui.service.PatientsService;
import com.vaadin.demo.ui.views.base.VerticalLayoutView;
import com.vaadin.demo.ui.views.patients.SubView;
import com.vaadin.demo.ui.views.patients.SubViewHeader;
import com.vaadin.demo.ui.views.patients.SubViewNavigator;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.ViewScope;
import com.vaadin.ui.*;
import com.vaadin.ui.themes.ValoTheme;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;

@SpringComponent
@ViewScope
public class ProfileEditView extends VerticalLayoutView implements SubView {

    private DoctorRepository doctorRepository;
    private PatientsService patientsService;
    private SubViewNavigator navigator;
    private BeanValidationBinder<Patient> binder;

    @Autowired
    public ProfileEditView(DoctorRepository doctorRepository, PatientsService patientsService, SubViewNavigator navigator) {
        addStyleName("profile-edit-view");
        this.doctorRepository = doctorRepository;
        this.patientsService = patientsService;
        this.navigator = navigator;
    }

    @PostConstruct
    void init() {
        setMargin(false);
        buildLayout();
    }

    @Override
    public void attach() {
        super.attach();
        addSubscription(patientsService.getCurrentPatient().subscribe(p -> p.ifPresent(this::updateFromPatient)));
    }

    private void updateFromPatient(Patient patient) {
        binder.setBean(patient);
    }

    private void buildLayout() {
        setDefaultComponentAlignment(Alignment.MIDDLE_CENTER);
        SubViewHeader header = new SubViewHeader(navigator, getTitle(), "profile");
        PatientFormLayout formLayout = new PatientFormLayout();
        formLayout.setWidth("80%");

        binder = new BeanValidationBinder<>(Patient.class);
        binder.forField(formLayout.birthDate).withConverter(new DateConverter()).bind("birthDate");
        binder.bindInstanceFields(formLayout);


        NativeButton saveButton = new NativeButton("Save");
        saveButton.addStyleName(ValoTheme.BUTTON_PRIMARY);
        NativeButton cancelButton = new NativeButton("Cancel");
        NativeButton deleteButton = new NativeButton("Delete");
        deleteButton.addStyleName(ValoTheme.BUTTON_DANGER);

        saveButton.addClickListener(click -> {
            try {
                binder.writeBean(binder.getBean());
                patientsService.savePatient(binder.getBean());
            } catch (ValidationException e) {
                Notification.show("Save failed", Notification.Type.WARNING_MESSAGE);
            }
        });

        cancelButton.addClickListener(click -> navigator.navigateTo("profile"));
        deleteButton.addClickListener(click -> {
            patientsService.deleteCurrentPatient();
        });

        addComponents(header, formLayout, new HorizontalLayout(saveButton, cancelButton, deleteButton));
    }

    @Override
    public String getUrl() {
        return "profile/edit";
    }

    @Override
    public String getTitle() {
        return "Editing Patient";
    }

    @Override
    public boolean isFullScreen() {
        return true;
    }


    class PatientFormLayout extends FormLayout {

        private final ComboBox<String> title;
        private final TextField firstName;
        private final TextField middleName;
        private final TextField lastName;
        private final ComboBox<Gender> gender;
        private final DateField birthDate;
        private final TextField ssn;
        private final ComboBox<Doctor> doctor;

        PatientFormLayout() {

            title = new ComboBox<>("Title");
            title.setItems("Miss", "Ms", "Mrs", "Mr");
            title.setEmptySelectionAllowed(false);

            firstName = new TextField("First Name");
            middleName = new TextField("Middle Name");
            lastName = new TextField("Last Name");

            gender = new ComboBox<>("Gender");
            gender.setItems(Gender.values());
            gender.setEmptySelectionAllowed(false);

            birthDate = new DateField("Date of Birth");
            ssn = new TextField("SSN");

            doctor = new ComboBox<>("Doctor");
            doctor.setItems(doctorRepository.findAll());
            doctor.setEmptySelectionAllowed(false);

            addComponents(title, firstName, middleName, lastName, gender, birthDate, ssn, doctor);
            iterator().forEachRemaining(c -> c.setWidth("100%"));
        }
    }

}
