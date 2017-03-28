package com.vaadin.demo.ui.views.patients.profile;


import com.vaadin.demo.entities.Patient;
import com.vaadin.demo.ui.service.PatientsService;
import com.vaadin.demo.ui.views.base.CssLayoutView;
import com.vaadin.demo.ui.views.patients.SubView;
import com.vaadin.server.ExternalResource;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.ViewScope;
import com.vaadin.ui.FormLayout;
import com.vaadin.ui.HorizontalLayout;
import com.vaadin.ui.Image;
import com.vaadin.ui.Label;
import org.springframework.beans.factory.annotation.Autowired;

import java.text.SimpleDateFormat;

@SpringComponent
@ViewScope
public class ProfileView extends CssLayoutView implements SubView {

    private final PatientsService patientsService;
    private final NameLayout nameLayout;
    private final Image picture;
    private final DetailsLayout detailsLayout;


    @Autowired
    public ProfileView(PatientsService patientsService) {
        addStyleName("profile-view");
        this.patientsService = patientsService;
        nameLayout = new NameLayout();
        detailsLayout = new DetailsLayout();
        picture = new Image();
        picture.addStyleName("profile-picture");
        addComponents(nameLayout, detailsLayout, picture);

    }

    @Override
    public String getUrl() {
        return "profile";
    }

    @Override
    public String getTitle() {
        return "Patient profile";
    }

    @Override
    public boolean isFullScreen() {
        return false;
    }

    @Override
    public void attach() {
        super.attach();
        addSubscription(patientsService.getCurrentPatient().subscribe(patient -> {
            patient.ifPresent(this::updateFromPatient);
        }));
    }

    private void updateFromPatient(Patient patient) {
        nameLayout.update(patient);
        detailsLayout.update(patient);
        picture.setSource(new ExternalResource(patient.getPictureUrl()));
    }


    class NameLayout extends HorizontalLayout {

        private final Label firstName;
        private final Label middleName;
        private final Label lastName;

        NameLayout() {
            addStyleName("name-layout");

            firstName = new Label();
            firstName.addStyleName("first-name");
            firstName.setCaption("First name");
            middleName = new Label();
            middleName.setCaption("Middle name");
            lastName = new Label();
            lastName.setCaption("Last name");

            addComponents(firstName, middleName, lastName);
        }

        void update(Patient patient) {
            firstName.setValue(patient.getFirstName());
            middleName.setValue(patient.getMiddleName());
            lastName.setValue(patient.getLastName());
        }
    }


    class DetailsLayout extends FormLayout {

        private final Label gender;
        private final Label dateOfBirth;
        private final Label ssn;
        private final Label patientId;
        private final Label doctor;
        private final Label medicalRecord;
        private final Label lastVisit;

        DetailsLayout() {
            addStyleName("details-layout");
            setSizeUndefined();

            gender = new Label();
            gender.setCaption("Gender");
            dateOfBirth = new Label();
            dateOfBirth.setCaption("Date of Birth");
            ssn = new Label();
            ssn.setCaption("SSN");
            patientId = new Label();
            patientId.setCaption("Patient ID");
            doctor = new Label();
            doctor.setCaption("Doctor");
            medicalRecord = new Label();
            medicalRecord.setCaption("Medical Record");
            lastVisit = new Label();
            lastVisit.setCaption("Last Visit");

            addComponents(gender, dateOfBirth, ssn, patientId, doctor, medicalRecord, lastVisit);
        }

        void update(Patient patient) {
            gender.setValue(patient.getGender() == null ? "" : patient.getGender().toString().substring(0, 1) + patient.getGender().toString().substring(1).toLowerCase());
            dateOfBirth.setValue(patient.getBirthDate() == null ? "" : SimpleDateFormat.getDateInstance().format(patient.getBirthDate()));
            ssn.setValue(patient.getSsn());
            patientId.setValue(patient.getId().toString());
            doctor.setValue(patient.getDoctor().toString());
            medicalRecord.setValue(patient.getMedicalRecord().toString());
            lastVisit.setValue(patient.getLastVisit() == null ? "" : SimpleDateFormat.getDateInstance().format(patient.getLastVisit()));


        }
    }
}


