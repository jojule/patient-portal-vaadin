package com.vaadin.demo.ui;

import com.vaadin.demo.entities.JournalEntry;
import com.vaadin.demo.entities.Patient;
import com.vaadin.demo.repositories.PatientRepository;
import com.vaadin.demo.service.PatientService;
import com.vaadin.demo.ui.mobile.MobileJournalRow;
import com.vaadin.server.ExternalResource;
import com.vaadin.server.FontAwesome;
import com.vaadin.shared.ui.ContentMode;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.UIScope;
import com.vaadin.ui.*;
import com.vaadin.ui.themes.ValoTheme;
import org.springframework.beans.factory.annotation.Autowired;

import java.text.SimpleDateFormat;
import java.util.Date;

@SpringComponent
@UIScope
public class PatientDetails extends SubView {

    @Autowired
    PatientRepository repo;

    @Autowired
    PatientService patientService;

    CssLayout profile = new CssLayout();
    VerticalLayout journal = new VerticalLayout();

    @Autowired
    PatientForm form = new PatientForm();

    @Autowired
    JournalEntryForm journalEntryForm;

    Button editBtn, addBtn, back;

    // Added last so we don't build the views again for no reason.
    private Patient patient, lastJournalPatient, lastProfilePatient;

    public PatientDetails() {
        getTabsheet().addSelectedTabChangeListener(event -> populate());

        initTabs();
        initButtons();

        addTab(profile);
        addTab(journal);

        setTopRightComponent(editBtn);
        setTopLeftComponent(back);

    }

    private void initTabs() {
        profile.setCaption("Profile");
        profile.addStyleName("content-layout");
        profile.setWidth("100%");

        journal.setCaption("Journal");
        journal.addStyleName("content-layout");
        journal.setSizeFull();
    }

    private void initButtons() {
        editBtn = new Button("Edit Patient");
        editBtn.addClickListener(e -> edit());
        editBtn.addStyleName(ValoTheme.BUTTON_BORDERLESS);
        editBtn.addStyleName("uppercase");

        addBtn = new Button("New Entry", FontAwesome.PLUS);
        addBtn.addClickListener(e -> addJournal());
        addBtn.addStyleName("addButton");

        back = new Button("All Patients", FontAwesome.ARROW_LEFT);
        back.addClickListener(e -> close());
        back.addStyleName(ValoTheme.BUTTON_BORDERLESS);
        back.addStyleName("uppercase");
    }

    @Override
    public void repaint() {
        showPatient(patient);
    }

    void showPatient(Patient p) {
        if (p.isPersistent()) {
            p = patientService.findAttached(p); // fetch with joins to history etc
        }
        patient = p;
        lastJournalPatient = lastProfilePatient = null;

        populate();

        show();
    }

    private void populate() {
        if (patient == null) {
            return;
        }
        updateLayoutStyles();

        Component selectedTab = getTabsheet().getSelectedTab();
        if (selectedTab.equals(profile)) {
            populateProfile();
        } else {
            populateJournal();
        }
    }

    private void updateLayoutStyles() {
        if (((VaadinUI) UI.getCurrent()).getLayoutMode().equals(LayoutMode.DESKTOP)) {
            profile.removeStyleName("mobile-profile");
            journal.removeStyleName("mobile-journal");
            removeStyleName("mobile");
            back.setCaption("All Patients");
        } else {
            profile.addStyleName("mobile-profile");
            journal.addStyleName("mobile-journal");
            addStyleName("mobile");
            back.setCaption(null);
        }
    }

    private void populateProfile() {
        if (patient.equals(lastProfilePatient)) {
            return;
        }
        profile.removeAllComponents();


        HorizontalLayout nameLayout = new HorizontalLayout();
        nameLayout.addComponent(getNameLabel(patient.getFirstName(), "First Name"));
        nameLayout.addComponent(getNameLabel(patient.getMiddleName(), "Middle Name"));
        nameLayout.addComponent(getNameLabel(patient.getLastName(), "Last Name"));
        nameLayout.setSpacing(true);


        // TODO BIND data, manually is the only option for read only?
        FormLayout fl = new FormLayout();
        fl.addStyleName("data-layout");
        fl.setMargin(false);
        fl.addComponent(createLabel("Gender", patient.getGender() == null ? "" : patient.getGender().toString().substring(0, 1) + patient.getGender().toString().substring(1).toLowerCase()));
        fl.addComponent(createLabel("Date of birth", patient.getBirthDate() == null ? "" : SimpleDateFormat.getDateInstance().format(patient.getBirthDate())));
        fl.addComponent(createLabel("Snn", patient.getSsn()));
        Label label = createLabel("Patient ID", patient.getId());
        // Add some height to get a small empty space in the form between Patient Id and Doctor
        label.setHeight("60px");
        fl.addComponent(label);
        fl.addComponent(createLabel("Doctor", patient.getDoctor()));
        fl.addComponent(createLabel("Medical record", patient.getMedicalRecord()));
        fl.addComponent(createLabel("Last visit", patient.getLastVisit() == null ? "" : SimpleDateFormat.getDateInstance().format(patient.getLastVisit())));

        if (((VaadinUI) UI.getCurrent()).getLayoutMode().equals(LayoutMode.DESKTOP)) {
            profile.addComponent(nameLayout);
        }

        // If we have a patient and can build the patient image url then add image.
        if (patient != null && patient.getGender() != null && patient.getId() != null) {
            Image image = new Image(null, new ExternalResource(getRandomImageUrl()));

            if (((VaadinUI) UI.getCurrent()).getLayoutMode().equals(LayoutMode.DESKTOP)) {
                HorizontalLayout infoLayout = new HorizontalLayout(fl, image);
                infoLayout.setWidth("100%");
                infoLayout.setExpandRatio(fl, 60);
                infoLayout.setExpandRatio(image, 40);
                infoLayout.setComponentAlignment(image, Alignment.MIDDLE_CENTER);

                profile.addComponent(infoLayout);
            } else {
                profile.addComponents(image, nameLayout, fl);
            }
        } else {
            profile.addComponent(fl);
        }
        lastProfilePatient = patient;
    }

    private Grid<JournalEntry> journalEntryGrid;

    private void populateJournal() {
        if (patient.equals(lastJournalPatient)) {
            return;
        }
        journal.removeAllComponents();

        Label patientName = new Label("<h2>" + patient.toString() + "</h2>", ContentMode.HTML);

        if (((VaadinUI) UI.getCurrent()).getLayoutMode().equals(LayoutMode.DESKTOP)) {
            HorizontalLayout header = new HorizontalLayout(patientName, addBtn);
            header.setWidth("100%");
            header.setComponentAlignment(patientName, Alignment.MIDDLE_LEFT);
            header.setComponentAlignment(addBtn, Alignment.MIDDLE_RIGHT);

            if (journalEntryGrid == null) {
                initJournalEntryGrid();
            }

            journalEntryGrid.setItems(patient.getJournalEntries());

            journal.addComponent(header);
            journal.addComponent(journalEntryGrid);
            journal.setExpandRatio(journalEntryGrid, 1f);
        } else {
            journal.addComponent(addBtn);
            journal.addComponent(patientName);

            VerticalLayout panelContent = new VerticalLayout();
            Panel journalEntriesPanel = new Panel(panelContent);
            journalEntriesPanel.setSizeFull();

            patient.getJournalEntries().forEach(journalEntry -> panelContent.addComponent(new MobileJournalRow(journalEntry)));

            journal.addComponent(journalEntriesPanel);
            journal.setExpandRatio(journalEntriesPanel, 1f);
        }

        lastJournalPatient = patient;
    }

    private void initJournalEntryGrid() {
        journalEntryGrid = new Grid<>();
        journalEntryGrid.addStyleName("open-close-selection");
        journalEntryGrid.addColumn(j -> SimpleDateFormat.getDateInstance().format(j.getDate())).setCaption("Date");
        journalEntryGrid.addColumn(j -> j.getAppointmentType().toString()).setCaption("Appointment");
        journalEntryGrid.addColumn(j -> j.getDoctor().toString()).setCaption("Doctor").setExpandRatio(1);
        journalEntryGrid.addColumn(JournalEntry::getEntry).setCaption("Notes").setExpandRatio(1).setMaximumWidth(400);

        journalEntryGrid.setDetailsGenerator(j -> {
            Label l = new Label(j.getEntry());
            l.setWidth("100%");
            l.setCaption("NOTES");
            VerticalLayout vl = new VerticalLayout(l);
            vl.setMargin(true);
            return vl;
        });

        journalEntryGrid.setHeight(100, Unit.PERCENTAGE);

        journalEntryGrid.addItemClickListener(e -> {
            journalEntryGrid.setDetailsVisible(e.getItem(), !journalEntryGrid.isDetailsVisible(e.getItem()));
        });


        journalEntryGrid.setWidth("100%");
    }

    private Label getNameLabel(String content, String caption) {
        Label label = createLabel(caption, content);
        label.addStyleName("name-label");
        label.addStyleName("uppercase");
        return label;
    }

    private Label createLabel(String caption, Object value) {
        Label l = new Label(value == null ? "" : value.toString());
        l.setCaption(caption);
        return l;
    }

    private void addJournal() {
        JournalEntry journalEntry = new JournalEntry();
        journalEntry.setDate(new Date());
        journalEntry.setPatient(patient);
        journalEntryForm.editJournal(journalEntry);
    }

    public void edit() {
        form.editPatient(patient);
    }

    /**
     * Generate a url to get a user image from teh randomuser.me API
     *
     * @return Image url for random user image.
     */
    public String getRandomImageUrl() {
        StringBuilder sb = new StringBuilder();
        sb.append("https://randomuser.me/api/portraits/");
        switch (patient.getGender()) {
            case MALE:
                sb.append("men/");
                break;
            case FEMALE:
                sb.append("women/");
                break;
        }
        sb.append(patient.getId() % 100).append(".jpg");
        return sb.toString();
    }
}
