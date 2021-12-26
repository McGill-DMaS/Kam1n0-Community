package ca.mcgill.sis.dmas.kam1n0.framework.storage;

import ca.mcgill.sis.dmas.env.StringResources;

public class CommentResult {
    public String functionId;
    public String functionOffset;
    public String userName = StringResources.STR_EMPTY;
    public long date;
    public String comment = StringResources.STR_EMPTY;
    public Comment.CommentType type = Comment.CommentType.regular;

    public CommentResult(Comment commentOriginal) {
        functionId  = String.valueOf(commentOriginal.functionId);
        functionOffset = commentOriginal.functionOffset;
        userName = commentOriginal.userName;
        date = commentOriginal.date;
        comment = commentOriginal.comment;
        type = commentOriginal.type;
    }
}
