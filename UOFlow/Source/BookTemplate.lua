----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

BookTemplate = {}

BookTemplate.OpenBooks = {}
BookTemplate.bDebug = 0

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function BookTemplate.Initialize()
	local bookId = WindowData.Book.ObjectId
	local bookWindowName = SystemData.ActiveWindow.name
	
 	BookTemplate.OpenBooks[bookId] = {}
	BookTemplate.OpenBooks[bookId]["pageNums"] = {0,1}
	BookTemplate.OpenBooks[bookId].canEdit = WindowData.Book.CanEdit
	BookTemplate.OpenBooks[bookId].numPages = WindowData.Book.NumPages
	BookTemplate.OpenBooks[bookId].author = WindowData.Book.Author
	BookTemplate.OpenBooks[bookId].title = WindowData.Book.Title

	WindowRegisterEventHandler(bookWindowName, SystemData.Events.BOOK_PAGE_DATA_RECIEVED, "BookTemplate.UpdatePageText")
	Interface.DestroyWindowOnClose[bookWindowName] = true
    WindowSetId (bookWindowName, WindowData.Book.ObjectId)   

    local titlePageWindowName = bookWindowName.."TitlePage"
    CreateWindowFromTemplate( titlePageWindowName, "TitlePageTemplate", bookWindowName )
	WindowAddAnchor( titlePageWindowName, "center", bookWindowName.."Page1", "center", 0, 0)

    WindowSetShowing(bookWindowName.."Page1EditText", false)
    WindowSetShowing(bookWindowName.."Page2EditText", false)

	if (WindowData.Book.CanEdit) then
		WindowSetShowing(titlePageWindowName.."Title", false)
		TextEditBoxSetText(titlePageWindowName.."EditTitle", WindowData.Book.Title)
		WindowAssignFocus(titlePageWindowName.."EditTitle",true)		
	else
		WindowSetShowing(titlePageWindowName.."EditTitle", false)
		LabelSetText(titlePageWindowName.."Title", WindowData.Book.Title)		
	end

    TextEditBoxSetHandleKeyDown(bookWindowName.."Page1EditText" ,WindowData.Book.CanEdit)
    TextEditBoxSetHandleKeyDown(bookWindowName.."Page2EditText" ,WindowData.Book.CanEdit)

	LabelSetText(titlePageWindowName.."Author",L"by\n\n"..BookTemplate.OpenBooks[bookId].author)
	LabelSetText(bookWindowName.."Page2Number", L"1")

	WindowSetShowing(bookWindowName.."PageDownButton", false)
	WindowSetShowing(bookWindowName.."PageUpButton", false)

    if (BookTemplate.OpenBooks[bookId].numPages > 1) then
        WindowSetShowing(bookWindowName.."PageUpButton", true)
    end

    TextEditBoxSetTextColor(bookWindowName.."Page1EditText", 148,49,49)
    TextEditBoxSetTextColor(bookWindowName.."Page2EditText", 148,49,49)
    TextEditBoxSetTextColor(titlePageWindowName.."EditTitle",0,0,0)
    LabelSetTextColor(titlePageWindowName.."Author",0,0,0)

       
    GumpManagerRequestBookPages(bookId, {1})
    WindowSetScale(bookWindowName, .9)    
end

function BookTemplate.Shutdown()
    local bookId = WindowGetId(SystemData.ActiveWindow.name)
    local bookWindowName =SystemData.ActiveWindow.name
    if( BookTemplate.OpenBooks[bookId].canEdit ) then
        BookTemplate.StoreText()
    end   
   
    BookTemplate.OpenBooks[bookId] = nil
end

function BookTemplate.CloseBook()
    UO_DefaultWindow.CloseDialog()    
end

function BookTemplate.PageUp()
    local bookId = WindowGetId(WindowUtils.GetActiveDialog())
    local bookWindowName = WindowUtils.GetActiveDialog()
    local requestPages = {}

    WindowSetShowing(bookWindowName.."PageUpButton", false)

	if (BookTemplate.OpenBooks[bookId]["pageNums"][1] + 2 <= BookTemplate.OpenBooks[bookId].numPages) then

		-- If previously at title page, show PageDownButton
	    if (BookTemplate.OpenBooks[bookId]["pageNums"][1] == 0) then
	        BookTemplate.EnterTitle()
			WindowSetShowing(bookWindowName.."PageDownButton", true)
    	end

    	-- If left page is last page
    	if (BookTemplate.OpenBooks[bookId]["pageNums"][1] + 2 == BookTemplate.OpenBooks[bookId].numPages) then
    	    requestPages[1] = BookTemplate.OpenBooks[bookId]["pageNums"][1] + 2
    	    
    	-- If both right and left pages contain text
    	else
    	    requestPages[1] = BookTemplate.OpenBooks[bookId]["pageNums"][1] + 2
    	    requestPages[2] = BookTemplate.OpenBooks[bookId]["pageNums"][2] + 2
		end
		
		if (BookTemplate.OpenBooks[bookId].canEdit) then
      		BookTemplate.StoreText()
    	end

        BookTemplate.OpenBooks[bookId]["pageNums"][1] = BookTemplate.OpenBooks[bookId]["pageNums"][1] + 2
        BookTemplate.OpenBooks[bookId]["pageNums"][2] = BookTemplate.OpenBooks[bookId]["pageNums"][2] + 2

        -- If there are more pages
		if (BookTemplate.OpenBooks[bookId]["pageNums"][1] + 2 <= BookTemplate.OpenBooks[bookId].numPages) then
		    WindowSetShowing(bookWindowName.."PageUpButton", true)
		end

        BookTemplate.UpdatePageNumbers()
    	GumpManagerRequestBookPages(bookId, requestPages)
    end
end

function BookTemplate.PageDown()
    local bookId = WindowGetId(WindowUtils.GetActiveDialog())
    local bookWindowName = WindowUtils.GetActiveDialog()
    local requestPages = {}
    
	if (BookTemplate.OpenBooks[bookId]["pageNums"][1] - 2 >= 0) then

		-- If going to title page, hide PageDownButton
	    if (BookTemplate.OpenBooks[bookId]["pageNums"][1] - 2 == 0) then
			WindowSetShowing(bookWindowName.."PageDownButton", false)

    	    requestPages[1] = BookTemplate.OpenBooks[bookId]["pageNums"][2] - 2

    	-- If both right and left pages contain text
    	else
			requestPages[1] = BookTemplate.OpenBooks[bookId]["pageNums"][1] - 2
    	    requestPages[2] = BookTemplate.OpenBooks[bookId]["pageNums"][2] - 2
		end
		
  		if (BookTemplate.OpenBooks[bookId].canEdit) then
      		BookTemplate.StoreText()
    	end

        BookTemplate.OpenBooks[bookId]["pageNums"][1] = BookTemplate.OpenBooks[bookId]["pageNums"][1] - 2
        BookTemplate.OpenBooks[bookId]["pageNums"][2] = BookTemplate.OpenBooks[bookId]["pageNums"][2] - 2

        -- If there are more pages
		if (BookTemplate.OpenBooks[bookId]["pageNums"][2] <= BookTemplate.OpenBooks[bookId].numPages) then
		    WindowSetShowing(bookWindowName.."PageUpButton", true)        
		end

        BookTemplate.UpdatePageNumbers()
    	GumpManagerRequestBookPages(bookId, requestPages)
    end
end

function BookTemplate.UpdatePageText()
    local bookWindowName = WindowUtils.GetActiveDialog()
    local bookId = WindowGetId(bookWindowName)
    local updateId = WindowData.Book.ObjectId
    local page1Set = false
    local page2Set = false

    if( bookId == updateId and BookTemplate.OpenBooks[bookId] ~= nil ) then
        for index,pageNum in ipairs(WindowData.Book.PageNums) do
            if( BookTemplate.OpenBooks[bookId]["pageNums"][1] ~= nil and BookTemplate.OpenBooks[bookId]["pageNums"][1] == pageNum ) then
                TextEditBoxSetText(bookWindowName.."Page1EditText", WindowData.Book.Pages[index])
                WindowSetShowing(bookWindowName.."Page1EditText", true)
                page1Set = true
            elseif( BookTemplate.OpenBooks[bookId]["pageNums"][1] ~= nil and BookTemplate.OpenBooks[bookId]["pageNums"][2] == pageNum ) then
                TextEditBoxSetText(bookWindowName.."Page2EditText", WindowData.Book.Pages[index])
                WindowSetShowing(bookWindowName.."Page2EditText", true)
                page2Set = true
            end
        end

        if (BookTemplate.OpenBooks[bookId]["pageNums"][1]  == 0) then
            TextEditBoxSetText(bookWindowName.."Page1EditText", L"")
            local titlePageWindowName = bookWindowName.."TitlePage"
            WindowSetShowing(titlePageWindowName, true)
            WindowSetShowing(bookWindowName.."Page1EditText", false)

            if (BookTemplate.OpenBooks[bookId].canEdit) then
				TextEditBoxSetText(titlePageWindowName.."EditTitle", BookTemplate.OpenBooks[bookId].title)
				WindowAssignFocus(titlePageWindowName.."EditTitle",true)
			end

        elseif( BookTemplate.OpenBooks[bookId]["pageNums"][1] == BookTemplate.OpenBooks[bookId].numPages) then
            WindowSetShowing(bookWindowName.."Page2EditText", false)
        elseif( BookTemplate.OpenBooks[bookId]["pageNums"][1]  ~= 0) then
            WindowSetShowing(bookWindowName.."TitlePage", false)            
        end
    end    
end

function BookTemplate.UpdatePageNumbers()
	local bookId = WindowGetId(WindowUtils.GetActiveDialog())
    local bookWindowName = WindowUtils.GetActiveDialog()
    
	if (BookTemplate.OpenBooks[bookId]["pageNums"][1]) then
		if (BookTemplate.OpenBooks[bookId]["pageNums"][1] == 0) then
			LabelSetText(bookWindowName.."Page1Number", L"")	
		else
			LabelSetText(bookWindowName.."Page1Number", StringToWString(tostring(BookTemplate.OpenBooks[bookId]["pageNums"][1])))
		end
	end
	if (BookTemplate.OpenBooks[bookId]["pageNums"][2] <= BookTemplate.OpenBooks[bookId].numPages) then
		LabelSetText(bookWindowName.."Page2Number", StringToWString(tostring(BookTemplate.OpenBooks[bookId]["pageNums"][2])))
    else
        LabelSetText(bookWindowName.."Page2Number", L"")
	end
end

function BookTemplate.EnterTitle()
	local bookWindowName = WindowUtils.GetActiveDialog()
    local bookId = WindowGetId(bookWindowName)
    local bookTitleEditBoxName = bookWindowName.."TitlePageEditTitle"
    
    BookTemplate.OpenBooks[bookId].title = TextEditBoxGetText(bookTitleEditBoxName)

    if (BookTemplate.OpenBooks[bookId].title) then
    	WindowAssignFocus(bookWindowName.."TitlePageEditTitle",false)
		GumpManagerSendAuthorTitle(bookId, BookTemplate.OpenBooks[bookId].title, BookTemplate.OpenBooks[bookId].author)
	end
end

function BookTemplate.StoreText()
    local bookWindowName = WindowUtils.GetActiveDialog()
    local bookId = WindowGetId(bookWindowName)
    local page1TextLines = TextEditBoxGetTextLines(bookWindowName.."Page1EditText")
	local page2TextLines = TextEditBoxGetTextLines(bookWindowName.."Page2EditText")

    local pageText1 = {}
    local pageText2 = {}
    pageNums = {}
    if( BookTemplate.OpenBooks[bookId]["pageNums"][1] == 0) then
        pageNums[1] = BookTemplate.OpenBooks[bookId]["pageNums"][2]
        pageText1 = page2TextLines
    else
        pageNums[1] = BookTemplate.OpenBooks[bookId]["pageNums"][1]
        pageText1 = page1TextLines

        pageNums[2] = BookTemplate.OpenBooks[bookId]["pageNums"][2]        
        pageText2 = page2TextLines
    end
    
	GumpManagerSendBookPages(bookId, pageNums, pageText1, pageText2)
end