package com.firmrec.rule;

import com.firmrec.utils.StringUtils;

public class CheckerRule {
    private String ruleId;
    private String ruleName;
    private boolean showResult;
    public CheckerRule(String checkerName) {
        this.ruleName = checkerName;
        this.ruleId = StringUtils.getRandomUUID();
        this.showResult = true;
    }

    public String getRuleId() {
        return this.ruleId;
    }

    public String getRuleName() {
        return this.ruleName;
    }

    public boolean isShowResult() {
        return showResult;
    }

    public void setShowResult(boolean showResult) {
        this.showResult = showResult;
    }
}
