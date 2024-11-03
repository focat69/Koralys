print('[/] Player Debugging Suite')

local function createUniquePlayerId(player: Player): string
    return tostring(player.UserId * 2.2331 / 3.1415 + 231.42213)
end

local players = {} -- Table to store all players (should have plaeyrs assorted to ids)
for _, player in next, game:GetService("Players"):GetPlayers() do
    players[createUniquePlayerId(player)] = {
        player = player,
        id = createUniquePlayerId(player),
        chatlogs = {},
        character = player.Character or player.CharacterAdded:Wait(),
        humanoid = player.Character:WaitForChild("Humanoid"),
        rootPart = player.Character:WaitForChild("HumanoidRootPart"),

        inventory = {
            items = {},
            equipped = nil
        },
        backpack = {}
    }

    player.Chatted:Connect(function(message)
        table.insert(players[createUniquePlayerId(player)].chatlogs, message)
    end)

    player.CharacterAdded:Connect(function(character)
        players[createUniquePlayerId(player)].character = character
        players[createUniquePlayerId(player)].humanoid = character:WaitForChild("Humanoid")
        players[createUniquePlayerId(player)].rootPart = character:WaitForChild("HumanoidRootPart")
    end)

    player.CharacterRemoving:Connect(function()
        players[createUniquePlayerId(player)].character = nil
        players[createUniquePlayerId(player)].humanoid = nil
        players[createUniquePlayerId(player)].rootPart = nil
    end)

    player:GetPropertyChangedSignal("Parent"):Connect(function()
        if player.Parent == nil then
            players[createUniquePlayerId(player)] = nil
        end
    end)

    -- Backpack (Stored)
    player.Backpack.ChildAdded:Connect(function(item)
        -- Clear backpack
        player.Backpack = {}
        -- Add tools to backpack
        for _, tool in next, player.Backpack:GetChildren() do
            if not tool:IsA("Tool") then continue end
            table.insert(players[createUniquePlayerId(player)].backpack, tool)
        end
    end)
    -- Inventory (Equipped)
    player.Character.ChildAdded:Connect(function(item)
        -- Clear inventory
        player.Inventory = {}
        -- Add tools to inventory
        if not item:IsA("Tool") then return end
        table.insert(players[createUniquePlayerId(player)].inventory.items, item)
    end)
end

local function lookupPlayer(player: Player)
    return players[createUniquePlayerId(player)]
end
local function lookupPlayerById(id: string)
    return players[id]
end
local function lookupPlayerByCharacter(character: Model)
    for _, player in next, players do
        if player.character == character then
            return player
        end
    end
end
local function lookupPlayerByHumanoid(humanoid: Humanoid)
    for _, player in next, players do
        if player.humanoid == humanoid then
            return player
        end
    end
end
local function lookupPlayerByRootPart(rootPart: BasePart)
    for _, player in next, players do
        if player.rootPart == rootPart then
            return player
        end
    end
end
local function getPlayerCharacter(player: Player)
    return players[createUniquePlayerId(player)].character
end
local function getPlayerHumanoid(player: Player)
    return players[createUniquePlayerId(player)].humanoid
end
local function getPlayerRootPart(player: Player)
    return players[createUniquePlayerId(player)].rootPart
end
local function getPlayerChatlogs(player: Player)
    return players[createUniquePlayerId(player)].chatlogs
end
local function getPlayerInventory(player: Player)
    return players[createUniquePlayerId(player)].inventory
end
local function getPlayerBackpack(player: Player)
    return players[createUniquePlayerId(player)].backpack
end

--< Export >--
local playerDebuggingSuite = {}

--< Export->Internal >--
playerDebuggingSuite._INTERNAL_createUniquePlayerId = createUniquePlayerId

--< Export->Lookup >--
playerDebuggingSuite.lookupPlayer = lookupPlayer
playerDebuggingSuite.lookupPlayerById = lookupPlayerById
playerDebuggingSuite.lookupPlayerByCharacter = lookupPlayerByCharacter
playerDebuggingSuite.lookupPlayerByHumanoid = lookupPlayerByHumanoid
playerDebuggingSuite.lookupPlayerByRootPart = lookupPlayerByRootPart

--< Export->Getters >--
playerDebuggingSuite.getPlayerCharacter = getPlayerCharacter
playerDebuggingSuite.getPlayerHumanoid = getPlayerHumanoid
playerDebuggingSuite.getPlayerRootPart = getPlayerRootPart
playerDebuggingSuite.getPlayerChatlogs = getPlayerChatlogs
playerDebuggingSuite.getPlayerInventory = getPlayerInventory
playerDebuggingSuite.getPlayerBackpack = getPlayerBackpack

return playerDebuggingSuite