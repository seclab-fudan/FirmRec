package com.firmrec.analyzer;

import com.firmrec.utils.IOUtils;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraJarApplicationLayout;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.*;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

public class GhidraWrapper {

    private final String rootDirectory;
    private String binaryPath;
    private String binaryName;

    private ProjectManager pm;
    private Project project;
    private Program program;
    private FlatProgramAPI flatProgramAPI;

    public GhidraWrapper(String directory) {
        this.rootDirectory = directory;

        GhidraApplicationLayout layout = getLayout();
        ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
        if (!Application.isInitialized()) {
            Application.initializeApplication(layout, configuration);
        }

        this.pm = new GhidraProjectManager();
    }

    /**
     * Public methods
     * */

    public ProgramAnalyzer loadBinary(String binaryPath, String languageId, Long baseAddress) {
        this.binaryPath = binaryPath;

        String[] pathItems = this.binaryPath.split("/");
        this.binaryName = pathItems[pathItems.length - 1];

//        String projectName = this.binaryName.replace(".", "_");
        String projectName = this.binaryName.replace(".", "_") + IOUtils.getFileMD5(this.binaryPath);
        Path projectDirectory = Path.of(this.rootDirectory, projectName);
        Project project = this.openProject(this.pm, projectDirectory);
        if (project == null) return null;
        this.project = project;

        File binaryFile = new File(this.binaryPath);
        Program program = this.loadExistsProgram(this.project);
        if (program == null) {
            program = this.loadNewProgram(binaryFile, this.project, languageId);

            if (baseAddress != null) {
                Address address = new FlatProgramAPI(program).toAddr(baseAddress);
                int txId = program.startTransaction("ChangeImageBase");
                try {
                    program.setImageBase(address, true);
                } catch (Exception e) {
                    System.out.println(e);
                } finally {
                    program.endTransaction(txId, true);
                }
            }

            this.analyzeProgram(program);
        }
        if (program == null) return null;
        this.program = program;

        this.flatProgramAPI = new FlatProgramAPI(this.program);
        return new ProgramAnalyzer(this.program, this.flatProgramAPI, this.binaryPath, projectDirectory.toString());
    }

    public void unloadBinary() {
        if (this.project == null) return;

        try {
            DomainFolder domainFolder = this.project.getProjectData().getRootFolder();
//            DomainFile df = domainFolder.createFile(this.binaryName, this.program, TaskMonitor.DUMMY);
            DomainFile df = domainFolder.getFile(this.binaryName);
            df.save(TaskMonitor.DUMMY);
        } catch (Exception e) {
            e.printStackTrace();
        }

        this.program.release(this);
        this.project.close();
    }

    /**
     * Private methods
     * */

    private static GhidraApplicationLayout getLayout() {
        GhidraApplicationLayout layout = null;
        try {
            layout = new GhidraJarApplicationLayout();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return layout;
    }

    private Project openProject(ProjectManager projectManager, Path projectDirectory) {
        if (projectManager == null) return null;

        // Confirm that project directory should exist
        String projectDirectoryStr = projectDirectory.toString();
        File projectFile = new File(projectDirectoryStr);
        if (!projectFile.exists()) {
            if (!projectFile.mkdir()) return null;
        }

        // Get the locator of project
        String projectPath = projectFile.getPath();
        String projectName = projectFile.getName() + ProjectLocator.getProjectExtension();
        ProjectLocator projectLocator = new ProjectLocator(projectPath, projectName);

        // Create or open the project
        Project project = null;
        if (projectLocator.getProjectDir().exists()) {
            try {
                project = projectManager.openProject(projectLocator, false, false);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            try {
                project = projectManager.createProject(projectLocator, null, false);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return project;
    }

    private Program loadExistsProgram(Project project) {
        Program program = null;

        DomainFolder domainFolder = project.getProjectData().getRootFolder();
        for (DomainFile domainFile : domainFolder.getFiles()) {
            try {
                DomainObject domainObject = domainFile.getDomainObject(this, true, true, TaskMonitor.DUMMY);
                if (domainObject instanceof Program) {
                    program = (Program) domainObject;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return program;
    }

    private Program loadNewProgram(File binaryFile, Project project, String languageId) {
        Program program = null;
        DomainFolder domainFolder = project.getProjectData().getRootFolder();

        MessageLog messageLog = new MessageLog();
        try {
            if (languageId == null) {
                program = AutoImporter.importByUsingBestGuess(binaryFile, null, this, messageLog, TaskMonitor.DUMMY);
            } else {
                Language language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
                program = AutoImporter.importByLookingForLcs(binaryFile, null, language, language.getDefaultCompilerSpec(), this,
                        messageLog, TaskMonitor.DUMMY);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (program == null) return null;

        try {
            DomainFile df = domainFolder.createFile(binaryFile.getName(), program, TaskMonitor.DUMMY);
            df.save(TaskMonitor.DUMMY);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return program;
    }

    private void analyzeProgram(Program program) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        mgr.initializeOptions();
        int txId = program.startTransaction("Analysis");

        mgr.reAnalyzeAll(null);
        mgr.startAnalysis(TaskMonitor.DUMMY);
        GhidraProgramUtilities.setAnalyzedFlag(program, true);

        program.endTransaction(txId, true);
    }

    private static class GhidraProjectManager extends DefaultProjectManager {
        // this exists just to allow access to the constructor
    }

}
