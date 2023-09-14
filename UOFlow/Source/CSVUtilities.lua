----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

CSVUtilities = {}

----------------------------------------------------------------
-- CSV File Helper Functions
----------------------------------------------------------------

function CSVUtilities.getNumRows(CSVTable)
    local numRows = 0
	if not CSVTable then
		return 0
	end
    for key, value in pairs(CSVTable) do
            numRows = numRows + 1         
    end
    
    return numRows       
end

-- Return the row # containing the specified column with the specified value
function CSVUtilities.getRowIdWithColumnValue(CSVTable, columnName, columnValue)        
        local numRows = CSVUtilities.getNumRows(CSVTable)
        local rowNumWithValue = nil

        for rowNum = 1,numRows do
                if (CSVTable[rowNum][columnName] == columnValue) then
                        rowNumWithValue = rowNum
                        break                
                end     
        end

        return rowNumWithValue        
end
