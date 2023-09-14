----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

MacroPickerWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

MacroPickerWindow.numMacrosPerRow = 4
MacroPickerWindow.MacroSelected = nil

MacroPickerWindow.MacroIcons = {
								0, 620,
								
								1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
								16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
								29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
								42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
								55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
								
								101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
								111, 112, 113, 114, 115, 116, 117,
								
								201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
								
								401, 402, 403, 404, 405, 406,
								
								501, 502, 503, 504, 505, 506, 507, 508,
								
								601, 602, 603, 604, 605, 606, 607, 608, 609, 610,
								611, 612, 613, 614, 615, 616,
								
								678, 679, 680, 681, 682, 683, 684, 685, 686, 687,
								
								688, 689, 690, 691, 692, 693,
				
								1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009,
								1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018,
								1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027,
								1028, 1029, 1030, 1031,
								
								2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
								2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018,
								2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027,
								2028, 2029, 2030, 2031, 2032, 2033, 2034, 2035, 2036,
								2037, 2038, 2039, 2040, 2041, 2042, 2043, 2044, 2045,
								2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 2054,
								2055, 2056, 2057, 2058,
								
								1701, 1702, 1703, 1704, 1705, 1706,
								
								03001, 03002, 03003, 03004, 03011, 03012, 03013, 03014, 
								03015, 03016, 03021, 03022, 03023, 03024, 03025, 
								
								700, 701, 702, 703, 704, 705, 706, 707,
								
								622, 624, 631, 632, 638, 639, 713, 714, 715, 
								855002, 855003, 855005, 855008, 855011, 855014, 
								855015, 855016, 855017, 855018, 855019, 855020, 
								855022, 855023, 855028, 855030, 
								
								662, 663, 664, 665, 667, 668, 669, 670, 672, 673, 
								674, 694, 695, 709, 710, 711, 712, 855025, 855026, 
								855027, 
								
								650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 
								660, 661, 855012, 855013, 855021, 855029, 
								
								635, 795, 796, 860001, 860002, 860003, 860004, 
								860005, 860006, 860007, 860008, 860009, 860010,
								860011, 860012, 860013, 860014, 860016, 
								
								618, 643, 644, 645, 771, 772, 797, 799, 
								
								646, 647, 648, 649, 708, 770, 775, 776, 777, 778, 
								779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 
								865000, 865001, 865002, 865003, 865004, 865005, 
								
								870000, 870001, 870002, 870003, 870004, 
								
								870050, 870051, 870052, 870053, 870054, 
								
								870100, 870101, 870102, 870103, 870104, 
								
								870150, 870151, 870152, 870153, 870154, 
								
								870200, 870201, 870202, 870203, 870204, 870205, 870206,
								870207, 870208, 870209, 870210, 870211, 870212, 870213,
								870214,
								
								798, 870300, 870301, 870302, 870303, 870304, 870305, 870306,
								870307, 870308, 870309, 870310, 870311,
								
								870400, 870401, 870402, 870403, 870404, 870405, 870406, 870407,
								870408,
								
								625, 637, 792, 875000, 875001, 875002, 875003, 875004, 875005,
								875006, 875007, 875008, 875009, 875010, 875011, 875012, 875013,
								875014, 875015, 875016, 875017, 875018, 875019, 875020, 875021,
								875022, 875023, 875024, 875025, 875026, 875027, 875028, 875029,
								875030, 875031, 875032, 875033, 875034, 875035, 875036,
								
								619, 623, 641, 718, 724, 729, 730, 731, 732, 789, 790, 791, 
								875100, 875101, 875102, 875103, 875104, 875105, 875106, 875107,
								875109, 875110, 875111, 875112, 875113, 875114, 875115,
								875116, 875117, 875118, 875119, 875120, 875121, 875122, 875123, 
								875124,
								
								875200, 875201, 875202, 875203, 875204, 875205, 875206,
								
								875250, 875251, 875252, 875253, 875254, 875255, 875256, 875257,
								875258, 875259, 875260, 875261, 875262, 875263, 875264, 875265,
								875266, 875267, 875268, 875269,
								
								875300, 875301, 875302, 875303, 875304, 875305, 875306, 875307, 
								875308, 875309, 875310,
								
								875350, 875351, 875352, 875353, 875354, 875355, 875356,
								
								875400, 875401, 875402, 875403, 875404, 875405, 875406, 875407, 
								875408, 875409, 875410, 875411, 875412, 875413, 875414, 875415, 
								875416, 875417,
								
								875450, 875451, 875452, 875453, 875454, 875455, 875456, 875457,
								875458, 875459, 875460,
								
								875500, 875501, 875502, 875503, 875504, 875505, 875506, 875507, 
								875508, 875509, 875510, 875511, 875512, 875513, 875514,
								
								617, 629, 640, 677, 793, 794, 875600,
								
								675, 676, 773, 774,
								
								633, 719, 200200, 200201, 200202, 200203, 200204, 200205, 200206, 
								200207, 200208, 200209, 200210, 200211, 200212, 200213, 200214, 
								200215, 200216, 200217, 200218, 200219, 200220, 200221, 200222, 
								200223, 
								
								200100, 200101, 200102, 200103, 200104, 200105, 200106, 
								200150, 200151, 200152, 200153, 200154, 200155, 200156, 
								200157, 200158, 
								
								856000, 856001, 856002, 856003, 856004, 856005, 856006, 856007, 
								856008, 856009, 856010, 856011, 856012, 856013, 856014, 856015, 
								856016, 856017, 856018, 
								
								856100, 856101, 856102, 856103, 856104, 856105, 856106, 856107, 
								856108, 856109, 856110, 856111, 856112, 856113, 856114, 856115, 
								856116, 856117, 856118, 856119, 856120, 856121, 856122, 856123, 
								856124, 856125, 856126, 856127, 856128, 856129, 856130, 856131, 
								856132, 856133, 856134, 856135, 856136, 856137, 856138, 856139, 
								856140, 
								
								857400, 857401, 857402, 857403, 857404, 857405, 857406, 857407, 
								857408, 857409, 857410, 857411, 857412, 857413, 857414, 857415, 
								857416, 857417, 857418, 857419, 857420, 857421, 857422, 857423, 
								857424, 857425, 857426, 857427, 857428, 857429,
							}

----------------------------------------------------------------
-- MainMenuWindow Functions
----------------------------------------------------------------

-- OnInitialize Handler
function MacroPickerWindow.Initialize()
	--Debug.Print("MacroPickerWindow.Initialize()")
	local this = SystemData.ActiveWindow.name
	local id = SystemData.DynamicWindowId
	WindowSetId(this, id)
	
	MacroPickerWindow[id] = {}
	
	Interface.DestroyWindowOnClose[this] = true
end

function MacroPickerWindow.SetNumMacrosPerRow(numMacrosPerRow)
	MacroPickerWindow.numMacrosPerRow = numMacrosPerRow        
end

function MacroPickerWindow.DrawMacroTable(parent)
	--Debug.Print("MacroPickerWindow.DrawMacroTable()")
	local numInRow = 0
    local firstRowWindow = nil
    local currentMacroWindowName = nil
    local relativeAnchorMacroWindowName = nil
    local iconTexture, x, y = nil

	local scrollChild = parent.."ViewScrollChild"

    for index, iconId in ipairs(MacroPickerWindow.MacroIcons) do
        currentMacroWindowName = scrollChild..tostring(iconId)
        CreateWindowFromTemplate( currentMacroWindowName, "MacroPickerItemTemplate", scrollChild )
        CreateWindowFromTemplate( currentMacroWindowName .. "BG", "MacroPickerItemBGTemplate", scrollChild )
        iconTexture, x, y = GetIconData(iconId)
        DynamicImageSetTexture(currentMacroWindowName, iconTexture, x, y)
        
        DynamicImageSetTexture(currentMacroWindowName .. "BG", MiniTexturePack.DB[MiniTexturePack.Current].texture .. "Icon", x, y)
        WindowAddAnchor(currentMacroWindowName .. "BG", "topleft", currentMacroWindowName , "topleft", 0,0)
		WindowSetId(currentMacroWindowName, iconId)
		
        if (index == 1) then 
            WindowAddAnchor( currentMacroWindowName, "topleft", scrollChild, "topleft", 0, 0)
            relativeAnchorMacroWindowName = currentMacroWindowName
            firstRowWindow = currentMacroWindowName
        elseif (numInRow < MacroPickerWindow.numMacrosPerRow-1) then
            WindowAddAnchor( currentMacroWindowName, "topright", relativeAnchorMacroWindowName, "topleft", 0, 0)
            numInRow = numInRow + 1
            relativeAnchorMacroWindowName = currentMacroWindowName
        elseif (numInRow == MacroPickerWindow.numMacrosPerRow-1) then
            WindowAddAnchor( currentMacroWindowName, "bottomleft", firstRowWindow, "topleft", 0, 0)
            numInRow = 0
            relativeAnchorMacroWindowName = currentMacroWindowName
            firstRowWindow =  currentMacroWindowName                     
        end                
    end
   
   ScrollWindowUpdateScrollRect(parent.."View")
end

function MacroPickerWindow.SetMacro()
    local parent = WindowGetParent(WindowGetParent(WindowGetParent(SystemData.ActiveWindow.name)))
    
	MacroPickerWindow.MacroSelected = WindowGetId(SystemData.ActiveWindow.name)
    WindowSetShowing(parent, false)
        
    MacroPickerWindow.AfterMacroSelectionFunction()
end

function MacroPickerWindow.AfterMacroSelectionFunction()
	return
end

function MacroPickerWindow.SetAfterMacroSelectionFunction(funcCall)
	MacroPickerWindow.AfterMacroSelectionFunction = funcCall        
end

function MacroPickerWindow.SetMacroId(macroId, parent)
	MacroPickerWindow.MacroSelected= macroId
    WindowSetShowing(parent, false)
end
