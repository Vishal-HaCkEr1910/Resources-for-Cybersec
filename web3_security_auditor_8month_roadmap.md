# Web3 Smart Contract Security Auditor — 8-Month Roadmap
### Designed for: C/Reverse Engineering background | Doing DSA alongside | 100% Free Resources | Blindly Followable

---

> **How to use this guide:** Every day is a single instruction. Follow it top to bottom. Do not jump ahead. Do not skip practice days. When a link is given, open it. When a task is given, do it. Treat every "Practice" block as an exam — no looking at answers before you attempt.

---

## GROUND RULES (read once, never again)

| Rule | What it means |
|---|---|
| **4 hrs/day** | 2 hrs study + 2 hrs hands-on practice. DSA takes your remaining time. |
| **No skipping** | Each day builds on the last. Missing 1 day = redo it the next morning first. |
| **Bug journal** | Keep a Notion/Obsidian file. Every vulnerability you learn → write it in your own words + one example. |
| **No copy-paste** | Every line of code you write must be typed manually. Muscle memory is real. |
| **Twitter/X** | Follow: @PatrickAlphaC @pashovkrum @bytes032 @0xOwenThurm @HickupHH3. Read their posts during breaks. Free education daily. |

---

---

# PHASE 1 — EVM & Solidity Foundation
## Months 1–2 (Days 1–60)
### Goal: Understand the EVM like you understand x86. Write and deploy contracts without tutorials.

---

## WEEK 1 — Blockchain & EVM Fundamentals (Days 1–7)

### Day 1 — What is the EVM, really?

**Study (2 hrs)**

1. Open this: https://www.youtube.com/watch?v=gyMwXuJrbJQ  
   → Watch: "Blockchain Basics" by Patrick Collins (first 2 hours of his 32hr course)  
   → Stop at timestamp 2:00:00

2. Open this: https://evm.codes  
   → Read the "About EVM" section. Don't memorize — just absorb the concept of the stack machine.

**Practice (2 hrs)**

- Open: https://remix.ethereum.org  
- Create a new file called `HelloWorld.sol`
- Type this manually (no copy-paste):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract HelloWorld {
    string public greet = "Hello, Web3";
    
    function setGreet(string memory _greet) public {
        greet = _greet;
    }
}
```

- Deploy it on the JavaScript VM in Remix
- Call `setGreet` with your name
- Call `greet` and see the output

**End of day checkpoint:** Can you explain what "deploy" means and why there's a transaction? If yes → Day 2.

---

### Day 2 — Solidity Types & Storage

**Study (2 hrs)**

1. Open: https://www.youtube.com/watch?v=gyMwXuJrbJQ  
   → Continue from 2:00:00 → watch until 4:00:00  
   → Topic: Variables, Types, Functions

2. Read this page completely: https://docs.soliditylang.org/en/latest/types.html  
   → Focus: Value types, Reference types, Mappings

**Practice (2 hrs)**

- In Remix, create `SimpleStorage.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract SimpleStorage {
    uint256 public favoriteNumber;
    mapping(address => uint256) public addressToFavoriteNumber;
    
    struct Person {
        string name;
        uint256 favoriteNumber;
    }
    
    Person[] public people;
    
    function store(uint256 _number) public {
        favoriteNumber = _number;
    }
    
    function retrieve() public view returns (uint256) {
        return favoriteNumber;
    }
    
    function addPerson(string memory _name, uint256 _number) public {
        people.push(Person(_name, _number));
        addressToFavoriteNumber[msg.sender] = _number;
    }
}
```

- Deploy and call every single function
- Add 3 people. Retrieve by index. Check the mapping.

**Bug journal entry:** Write down what `memory` vs `storage` means in Solidity.

---

### Day 3 — Functions, Visibility, Modifiers

**Study (2 hrs)**

1. Continue Patrick's video: 4:00:00 → 6:00:00  
   → Topic: Function visibility, view/pure, payable

2. Read: https://docs.soliditylang.org/en/latest/contracts.html#visibility-and-getters

**Practice (2 hrs)**

Build a `FundMe.sol` contract in Remix:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract FundMe {
    address public owner;
    mapping(address => uint256) public addressToAmount;
    address[] public funders;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function fund() public payable {
        require(msg.value > 0, "Send ETH");
        addressToAmount[msg.sender] += msg.value;
        funders.push(msg.sender);
    }
    
    function withdraw() public onlyOwner {
        for (uint256 i = 0; i < funders.length; i++) {
            addressToAmount[funders[i]] = 0;
        }
        funders = new address[](0);
        (bool success, ) = payable(owner).call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
```

- Deploy and test: fund from 3 different accounts → try to withdraw from a non-owner → withdraw from owner

**Bug journal entry:** What does `modifier` do? Why is `require` important for security?

---

### Day 4 — EVM Opcodes & Storage Layout

**Study (2 hrs)**

1. Read this entire series (it's short articles): https://noxx.substack.com/p/evm-deep-dives-the-path-to-shadowy  
   → Read Part 1 and Part 2 today

2. Open: https://evm.codes  
   → Study these opcodes one by one: PUSH1, MLOAD, MSTORE, SLOAD, SSTORE, CALL, DELEGATECALL, STATICCALL  
   → For each: understand what it does and how much gas it costs

**Practice (2 hrs)**

- In Remix, write this contract and look at its bytecode:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract StorageLayout {
    uint256 public a = 1;      // slot 0
    uint256 public b = 2;      // slot 1
    address public c;          // slot 2
    uint128 public d = 10;     // slot 3 (first 16 bytes)
    uint128 public e = 20;     // slot 3 (last 16 bytes)
}
```

- After deploying, go to Remix → Debugger tab  
- Deploy the contract. Click on the deploy transaction → Debug  
- Step through the opcodes. Watch SSTORE being called for each variable  
- Open Remix's "Storage" panel and verify which slot each variable is in

**Bug journal entry:** What is a storage slot? Why does packing matter? What happens when you pack two uint128 into one slot?

---

### Day 5 — Inheritance, Interfaces, Libraries

**Study (2 hrs)**

1. Patrick Collins video: 6:00:00 → 8:00:00  
   → Topic: Inheritance, interfaces, abstract contracts

2. Read: https://docs.soliditylang.org/en/latest/contracts.html#inheritance

**Practice (2 hrs)**

Build this in Remix:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

interface IAnimal {
    function sound() external pure returns (string memory);
    function legs() external pure returns (uint256);
}

abstract contract Animal is IAnimal {
    string public name;
    
    constructor(string memory _name) {
        name = _name;
    }
}

contract Dog is Animal {
    constructor() Animal("Dog") {}
    
    function sound() public pure override returns (string memory) {
        return "Woof";
    }
    
    function legs() public pure override returns (uint256) {
        return 4;
    }
}

contract Snake is Animal {
    constructor() Animal("Snake") {}
    
    function sound() public pure override returns (string memory) {
        return "Hiss";
    }
    
    function legs() public pure override returns (uint256) {
        return 0;
    }
}
```

- Deploy Dog and Snake separately  
- Create a third contract that takes an `IAnimal` address and calls `sound()` and `legs()` on it  
- Pass Dog's deployed address to it — confirm it works

---

### Day 6 — Events, Errors, ABI Encoding

**Study (2 hrs)**

1. Watch: https://www.youtube.com/watch?v=gyMwXuJrbJQ → 8:00:00 to 10:00:00  

2. Read: https://docs.soliditylang.org/en/latest/abi-spec.html  
   → Read sections: "Function Selector" and "Argument Encoding" only

**Practice (2 hrs)**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract EventsAndErrors {
    error NotOwner(address caller);
    error InsufficientBalance(uint256 requested, uint256 available);
    
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Deposit(address indexed who, uint256 amount);
    
    address public owner;
    mapping(address => uint256) public balances;
    
    constructor() { owner = msg.sender; }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function transfer(address _to, uint256 _amount) public {
        if (balances[msg.sender] < _amount) {
            revert InsufficientBalance(_amount, balances[msg.sender]);
        }
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        emit Transfer(msg.sender, _to, _amount);
    }
    
    function getSelector(string memory _sig) public pure returns (bytes4) {
        return bytes4(keccak256(bytes(_sig)));
    }
}
```

- Deploy. Deposit 1 ETH. Transfer. Trigger the error.  
- Call `getSelector("transfer(address,uint256)")` and verify it matches what you see in the ABI

**Bug journal entry:** What is a function selector? How is it computed? Why does it matter for security?

---

### Day 7 — REVIEW DAY

**No new content today.**

**Morning (2 hrs):** Redo the SimpleStorage + FundMe contracts from memory. No looking at previous code.

**Afternoon (2 hrs):**

1. Go to: https://cryptozombies.io  
   → Complete Lessons 1 and 2 (Solidity 1 & 2)  
   → These are gamified — they will reinforce everything from this week interactively

**Self-check:** Without looking at anything, can you answer these?
- What are the 3 data locations in Solidity?
- What is storage slot 0?
- What does `indexed` do in an event?
- What is a function selector?

If you can't answer all 4 → reread your bug journal before Day 8.

---

## WEEK 2 — Advanced Solidity (Days 8–14)

### Day 8 — ERC20 Token Standard

**Study (2 hrs)**

1. Read the EIP: https://eips.ethereum.org/EIPS/eip-20  
   → Read the entire spec. Every function. Every event. Every rule.

2. Read OpenZeppelin's implementation: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol  
   → Read every line. Add comments in your own words next to each function.

**Practice (2 hrs)**

Build your own ERC20 from scratch WITHOUT using OpenZeppelin:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract MyToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor(string memory _name, string memory _symbol, uint256 _supply) {
        name = _name;
        symbol = _symbol;
        totalSupply = _supply * 10**decimals;
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }
    
    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balanceOf[msg.sender] >= _value, "Insufficient balance");
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(balanceOf[_from] >= _value, "Insufficient balance");
        require(allowance[_from][msg.sender] >= _value, "Insufficient allowance");
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
}
```

- Deploy and test the full approve → transferFrom flow  
- What happens if you approve 100 tokens but try to transferFrom 101?

---

### Day 9 — ERC721 NFT Standard

**Study (2 hrs)**

1. Read: https://eips.ethereum.org/EIPS/eip-721 — entire spec  
2. Read OZ implementation: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol

**Practice (2 hrs)**

Build a minimal NFT in Remix:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract SimpleNFT {
    string public name = "MyNFT";
    string public symbol = "MNFT";
    uint256 public nextTokenId;
    
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => mapping(address => bool)) public isApprovedForAll;
    
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    
    function mint(address _to) public {
        uint256 tokenId = nextTokenId++;
        ownerOf[tokenId] = _to;
        balanceOf[_to]++;
        emit Transfer(address(0), _to, tokenId);
    }
    
    function transferFrom(address _from, address _to, uint256 _tokenId) public {
        require(ownerOf[_tokenId] == _from, "Not owner");
        require(
            msg.sender == _from || 
            getApproved[_tokenId] == msg.sender || 
            isApprovedForAll[_from][msg.sender],
            "Not authorized"
        );
        ownerOf[_tokenId] = _to;
        balanceOf[_from]--;
        balanceOf[_to]++;
        getApproved[_tokenId] = address(0);
        emit Transfer(_from, _to, _tokenId);
    }
    
    function approve(address _to, uint256 _tokenId) public {
        require(ownerOf[_tokenId] == msg.sender, "Not owner");
        getApproved[_tokenId] = _to;
        emit Approval(msg.sender, _to, _tokenId);
    }
}
```

---

### Day 10 — Proxy Patterns & Delegatecall (CRITICAL FOR SECURITY)

**Study (2 hrs)**

1. Read: https://noxx.substack.com/p/evm-deep-dives-the-path-to-shadowy-d6b  
   → This is Part 3 of the EVM Deep Dive series — all about DELEGATECALL

2. Watch: https://www.youtube.com/watch?v=bdXJmWajZRY  
   → "Delegate Call" by Smart Contract Programmer

3. Read: https://docs.openzeppelin.com/contracts/4.x/api/proxy  

**Practice (2 hrs)**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// The logic contract
contract Logic {
    uint256 public value;
    address public sender;
    
    function setValue(uint256 _val) public {
        value = _val;
        sender = msg.sender;
    }
}

// The proxy contract
contract Proxy {
    uint256 public value;  // MUST match Logic storage layout
    address public sender; // MUST match Logic storage layout
    address public logicAddress;
    
    constructor(address _logic) {
        logicAddress = _logic;
    }
    
    fallback() external payable {
        (bool success, ) = logicAddress.delegatecall(msg.data);
        require(success, "delegatecall failed");
    }
    
    receive() external payable {}
}
```

- Deploy Logic first. Copy its address.  
- Deploy Proxy with Logic's address.  
- Call `setValue(42)` on the Proxy (not Logic)  
- Check `value` on Proxy — it should be 42  
- Check `sender` on Proxy — it should be YOUR address, not Logic's  
- Check `value` on Logic — it should still be 0 (untouched)  

**Bug journal entry (CRITICAL):** Why does Proxy have the same variable names as Logic? What happens if the storage layout doesn't match? This is a REAL vulnerability class called "Storage Collision."

---

### Day 11 — Assembly & Low-level Calls

**Study (2 hrs)**

1. Read: https://docs.soliditylang.org/en/latest/assembly.html — entire page  
2. Watch: https://www.youtube.com/watch?v=r4yKide6gZo  
   → "Yul / Inline Assembly" by Smart Contract Programmer

**Practice (2 hrs)**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract AssemblyPractice {
    // Read storage slot directly
    function getStorageAt(uint256 slot) public view returns (bytes32 value) {
        assembly {
            value := sload(slot)
        }
    }
    
    // Write to arbitrary storage slot
    function setStorageAt(uint256 slot, uint256 value) public {
        assembly {
            sstore(slot, value)
        }
    }
    
    // Get caller without msg.sender
    function getCaller() public view returns (address caller) {
        assembly {
            caller := caller()
        }
    }
    
    // Efficient ETH transfer
    function sendETH(address _to) public payable {
        assembly {
            let success := call(gas(), _to, callvalue(), 0, 0, 0, 0)
            if iszero(success) { revert(0, 0) }
        }
    }
}
```

- Deploy and experiment with every function  
- Call `setStorageAt(0, 999)` then `getStorageAt(0)` — watch the raw bytes

---

### Day 12 — Gas Optimization & Patterns

**Study (2 hrs)**

1. Read: https://github.com/0xKitsune/solidity-gas-optimizations — entire README  
2. Read: https://www.rareskills.io/post/gas-optimization — all sections

**Practice (2 hrs)**

Compare gas costs in Remix using the gas reporter. Write two versions of the same contract — one unoptimized, one optimized:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// BAD: expensive version
contract GasBad {
    uint256 public total;
    uint256[] public numbers;
    
    function addNumbers(uint256[] memory _nums) public {
        for (uint256 i = 0; i < _nums.length; i++) {
            numbers.push(_nums[i]);
            total += _nums[i];
        }
    }
}

// GOOD: optimized version
contract GasGood {
    uint256 public total;
    uint256[] public numbers;
    
    function addNumbers(uint256[] calldata _nums) public {  // calldata not memory
        uint256 len = _nums.length;         // cache length
        uint256 localTotal = total;         // cache storage var
        for (uint256 i; i < len; ) {        // uninitialized i saves gas
            numbers.push(_nums[i]);
            localTotal += _nums[i];
            unchecked { ++i; }              // unchecked increment
        }
        total = localTotal;                 // single SSTORE
    }
}
```

- Deploy both. Call `addNumbers([1,2,3,4,5])` on each. Compare gas used.

---

### Day 13 — CryptoZombies Completion + Review

**Full day:**

1. Go to: https://cryptozombies.io  
   → Complete Lessons 3, 4, 5 (Advanced Solidity, Payments, ERC721)  
   → These are critical — they cover payable, ERC721, and attack vectors in a gamified way

2. After completing, open your bug journal and write a 1-paragraph summary of everything you've learned in 2 weeks.

---

### Day 14 — MINI PROJECT: Build a simple DEX

**This is your first solo build. No guidance. Use what you know.**

Build a contract in Remix that:
- Has two ERC20 tokens (deploy two from Day 8)
- Lets users add liquidity (deposit both tokens)
- Lets users swap Token A for Token B at a fixed 1:1 rate
- Lets liquidity providers withdraw their share

Do not look up DEX tutorials. Try for 2 hours. If stuck, look at Uniswap V1 (simplest): https://github.com/Uniswap/v1-contracts/blob/master/contracts/uniswap_exchange.vy

**This project is your benchmark. Save it.**

---

## WEEK 3 — Foundry Setup & Testing (Days 15–21)

### Day 15 — Install Foundry + First Project

**Study (2 hrs)**

1. Read: https://book.getfoundry.sh/getting-started/installation  
   → Install Foundry right now:
   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. Read: https://book.getfoundry.sh/projects/creating-a-new-project

**Practice (2 hrs)**

Open your terminal:
```bash
forge init my-first-project
cd my-first-project
```

Open the project in VS Code. Look at the structure:
- `src/` — your contracts
- `test/` — your tests
- `script/` — deployment scripts
- `foundry.toml` — config

Replace `src/Counter.sol` with your FundMe contract from Day 3. Then run:
```bash
forge build
forge test
```

---

### Day 16 — Writing Foundry Unit Tests

**Study (2 hrs)**

1. Read: https://book.getfoundry.sh/forge/tests  
2. Read: https://book.getfoundry.sh/reference/forge-std/  

**Practice (2 hrs)**

Write tests for your FundMe contract:

```solidity
// test/FundMeTest.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {Test, console} from "forge-std/Test.sol";
import {FundMe} from "../src/FundMe.sol";

contract FundMeTest is Test {
    FundMe public fundMe;
    address public USER = makeAddr("user");
    uint256 public constant SEND_VALUE = 0.1 ether;
    uint256 public constant STARTING_BALANCE = 10 ether;
    
    function setUp() public {
        fundMe = new FundMe();
        vm.deal(USER, STARTING_BALANCE); // give USER some ETH
    }
    
    function testOwnerIsDeployer() public view {
        assertEq(fundMe.owner(), address(this));
    }
    
    function testFundFailsWithZeroETH() public {
        vm.expectRevert();
        fundMe.fund{value: 0}();
    }
    
    function testFundUpdatesFundersMapping() public {
        vm.prank(USER); // next call is from USER
        fundMe.fund{value: SEND_VALUE}();
        assertEq(fundMe.addressToAmount(USER), SEND_VALUE);
    }
    
    function testOnlyOwnerCanWithdraw() public {
        vm.prank(USER);
        fundMe.fund{value: SEND_VALUE}();
        
        vm.prank(USER);
        vm.expectRevert();
        fundMe.withdraw();
    }
    
    function testWithdrawFromOwner() public {
        vm.prank(USER);
        fundMe.fund{value: SEND_VALUE}();
        
        uint256 ownerStart = address(this).balance;
        fundMe.withdraw();
        uint256 ownerEnd = address(this).balance;
        
        assertEq(ownerEnd - ownerStart, SEND_VALUE);
        assertEq(address(fundMe).balance, 0);
    }
}
```

Run: `forge test -vvv`

---

### Day 17 — Foundry Cheatcodes (Your Security Superpower)

**Study (2 hrs)**

1. Read: https://book.getfoundry.sh/cheatcodes/  
   → Read ALL cheatcodes. These are your most important tools for security testing.  
   → Key ones to master: `vm.prank`, `vm.deal`, `vm.expectRevert`, `vm.warp`, `vm.roll`, `vm.store`, `vm.load`, `vm.startPrank`, `vm.stopPrank`

**Practice (2 hrs)**

Write a contract with a time-lock and test it:

```solidity
// src/TimeLock.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract TimeLock {
    address public owner;
    uint256 public lockTime;
    uint256 public constant LOCK_PERIOD = 1 days;
    
    constructor() {
        owner = msg.sender;
        lockTime = block.timestamp + LOCK_PERIOD;
    }
    
    function withdraw() public {
        require(msg.sender == owner, "Not owner");
        require(block.timestamp >= lockTime, "Still locked");
        payable(owner).transfer(address(this).balance);
    }
    
    receive() external payable {}
}
```

```solidity
// test/TimeLockTest.t.sol
import {Test} from "forge-std/Test.sol";
import {TimeLock} from "../src/TimeLock.sol";

contract TimeLockTest is Test {
    TimeLock lock;
    
    function setUp() public {
        lock = new TimeLock();
        vm.deal(address(lock), 1 ether);
    }
    
    function testCannotWithdrawBeforeLock() public {
        vm.expectRevert("Still locked");
        lock.withdraw();
    }
    
    function testCanWithdrawAfterLock() public {
        vm.warp(block.timestamp + 1 days + 1); // warp time
        uint256 before = address(this).balance;
        lock.withdraw();
        assertGt(address(this).balance, before);
    }
}
```

---

### Day 18 — Fork Testing (Test Against Real Protocols)

**Study (2 hrs)**

1. Read: https://book.getfoundry.sh/forge/fork-testing

**Practice (2 hrs)**

Fork mainnet and interact with real DAI:

```bash
# In foundry.toml, add:
# [rpc_endpoints]
# mainnet = "https://eth-mainnet.g.alchemy.com/v2/demo"
```

```solidity
// test/ForkTest.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

contract ForkTest is Test {
    address constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant DAI_WHALE = 0x28C6c06298d514Db089934071355E5743bf21d60;
    
    IERC20 dai;
    
    function setUp() public {
        // Fork mainnet at latest block
        vm.createSelectFork("https://eth-mainnet.g.alchemy.com/v2/demo");
        dai = IERC20(DAI);
    }
    
    function testDaiBalance() public view {
        uint256 balance = dai.balanceOf(DAI_WHALE);
        console.log("DAI balance:", balance);
        assertGt(balance, 0);
    }
    
    function testImpersonateWhale() public {
        vm.prank(DAI_WHALE);
        dai.transfer(address(this), 1000 ether);
        assertEq(dai.balanceOf(address(this)), 1000 ether);
    }
}
```

Run: `forge test --fork-url https://eth.llamarpc.com -vvv`

**Bug journal entry:** Why is `vm.prank` the most powerful cheatcode for security research?

---

### Day 19 — Fuzz Testing Basics

**Study (2 hrs)**

1. Read: https://book.getfoundry.sh/forge/fuzz-testing  
2. Read: https://book.getfoundry.sh/forge/invariant-testing

**Practice (2 hrs)**

```solidity
// src/SafeMath.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract SafeMath {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
    
    function sub(uint256 a, uint256 b) public pure returns (uint256) {
        require(b <= a, "underflow");
        return a - b;
    }
    
    function div(uint256 a, uint256 b) public pure returns (uint256) {
        require(b > 0, "div by zero");
        return a / b;
    }
}
```

```solidity
// test/FuzzTest.t.sol
import {Test} from "forge-std/Test.sol";
import {SafeMath} from "../src/SafeMath.sol";

contract FuzzTest is Test {
    SafeMath math;
    
    function setUp() public {
        math = new SafeMath();
    }
    
    // Foundry auto-generates random inputs for fuzz functions
    function testFuzz_AddIsCommutative(uint256 a, uint256 b) public {
        // Bound to avoid overflow
        a = bound(a, 0, type(uint128).max);
        b = bound(b, 0, type(uint128).max);
        assertEq(math.add(a, b), math.add(b, a));
    }
    
    function testFuzz_SubNeverUnderflows(uint256 a, uint256 b) public {
        vm.assume(b <= a); // skip cases where b > a
        assertGe(math.sub(a, b), 0);
    }
    
    function testFuzz_DivNeverDividesByZero(uint256 a, uint256 b) public {
        vm.assume(b > 0);
        math.div(a, b); // should never revert
    }
}
```

Run: `forge test --fuzz-runs 10000 -vvv`

---

### Day 20 — Invariant Testing (Advanced Fuzzing)

**Study (2 hrs)**

1. Read: https://book.getfoundry.sh/forge/invariant-testing — entire page  
2. Read: https://www.youtube.com/watch?v=juyY-CTolac  
   → Patrick Collins: "Invariant Testing"

**Practice (2 hrs)**

```solidity
// src/Bank.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract Bank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposited += msg.value;
    }
    
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient");
        balances[msg.sender] -= _amount;
        totalDeposited -= _amount;
        payable(msg.sender).transfer(_amount);
    }
}
```

```solidity
// test/BankInvariant.t.sol
import {Test, StdInvariant} from "forge-std/Test.sol";
import {Bank} from "../src/Bank.sol";

contract BankInvariant is StdInvariant, Test {
    Bank bank;
    
    function setUp() public {
        bank = new Bank();
        targetContract(address(bank)); // Foundry will fuzz this contract
    }
    
    // INVARIANT: contract ETH balance must always equal totalDeposited
    function invariant_balanceAlwaysMatchesTotal() public view {
        assertEq(address(bank).balance, bank.totalDeposited());
    }
    
    // INVARIANT: no single user can have more than the total
    function invariant_noOverdraft() public view {
        assertLe(bank.balances(address(this)), bank.totalDeposited());
    }
}
```

---

### Day 21 — REVIEW + Cyfrin Updraft Signup

**Day:**

1. Go to: https://updraft.cyfrin.io  
   → Create a free account  
   → Enroll in: "Foundry Fundamentals" course  
   → Watch the first 3 modules today (they recap everything you've done this week)

2. Review your bug journal. Rewrite anything that's unclear.

3. Run Foundry tests on all contracts you've built so far. Fix any that fail.

---

## WEEK 4 — Cyfrin Security Course Begins (Days 22–28)

### Days 22–28 — Cyfrin Updraft: Smart Contract Security

**Every day this week:**

1. Go to: https://updraft.cyfrin.io  
   → Open: "Smart Contract Security" course  
   → Watch and code along with 1–2 modules per day

**Exact module order to follow:**

| Day | Module to complete |
|---|---|
| Day 22 | Module 1: Introduction to Smart Contract Security + Audit Methodology |
| Day 23 | Module 2: Your First Audit — Static Analysis with Slither |
| Day 24 | Module 3: Re-entrancy Attacks (code + exploit + fix) |
| Day 25 | Module 4: Weak Randomness + Access Control |
| Day 26 | Module 5: Integer Overflow + Denial of Service |
| Day 27 | Module 6: MEV + Front-running + Tx ordering |
| Day 28 | Module 7: Signature replay + Missing validations |

**For each module:** Watch the lesson → Code along in Foundry → Write a bug journal entry.

---

---

# PHASE 2 — Security Wargames & Core Vulnerabilities
## Months 3–5 (Days 61–150)
### Goal: Pattern-match bugs on sight. Solve 80+ challenges. Build your exploit toolkit.

---

## WEEK 5 — Secureum Bootcamp (Days 29–35)

### Days 29–35 — Secureum Modules 1–4

**Every day:**

1. Go to: https://secureum.substack.com  
   → Read and study one module per day:

| Day | Secureum Module | Link |
|---|---|---|
| Day 29 | Epoch 0 — RACE 1 (Ethereum 101) | secureum.substack.com |
| Day 30 | Epoch 0 — RACE 2 (Solidity 101) | secureum.substack.com |
| Day 31 | Epoch 0 — RACE 3 (Solidity 201) | secureum.substack.com |
| Day 32 | Epoch 0 — RACE 4 (Pitfalls 101) | secureum.substack.com |
| Day 33 | Epoch 0 — RACE 5 (Pitfalls 201) | secureum.substack.com |
| Day 34 | Epoch 0 — RACE 6 (Audit Techniques) | secureum.substack.com |
| Day 35 | Take all 6 quizzes and score yourself |

**For each quiz:** Attempt all questions before checking answers. Every wrong answer → read why → bug journal entry.

---

## WEEKS 6–7 — Ethernaut Wargame (Days 36–50)

### The Rules of Wargames:
1. Read the challenge description
2. Read the contract code
3. Attempt exploit for **minimum 45 minutes** before looking for hints
4. Write your exploit in Foundry as a test
5. Write a 1-paragraph writeup after solving

---

**Go to: https://ethernaut.openzeppelin.com**

| Day | Level(s) | Vulnerability |
|---|---|---|
| Day 36 | Level 0 — Hello Ethernaut | Warmup |
| Day 37 | Level 1 — Fallback | Fallback functions + ownership |
| Day 38 | Level 2 — Fal1out | Constructor name bug (historical) |
| Day 39 | Level 3 — Coin Flip | Weak randomness |
| Day 40 | Level 4 — Telephone | tx.origin vs msg.sender |
| Day 41 | Level 5 — Token | Integer underflow (pre-0.8) |
| Day 42 | Level 6 — Delegation | Delegatecall exploit |
| Day 43 | Level 7 — Force | selfdestruct to force ETH |
| Day 44 | Level 8 — Vault | Private variable isn't private |
| Day 45 | Level 9 — King | DoS via ETH rejection |
| Day 46 | Level 10 — Re-entrancy | THE classic re-entrancy attack |
| Day 47 | Level 11 — Elevator | Interface manipulation |
| Day 48 | Level 12 — Privacy | Storage layout + slot reading |
| Day 49 | Level 13 — Gatekeeper One | ABI encoding + gas manipulation |
| Day 50 | Level 14 — Gatekeeper Two | extcodesize bypass |

**For each challenge:** Write your exploit as a Foundry fork test. Save all in a GitHub repo called `ethernaut-solutions`.

**Reference for hints (ONLY after 45 min attempt):** https://github.com/ciaranmcveigh5/ethernaut  

---

## WEEKS 7–8 — Ethernaut Continued (Days 51–60)

| Day | Level(s) | Vulnerability |
|---|---|---|
| Day 51 | Level 15 — Naught Coin | ERC20 approval bypass |
| Day 52 | Level 16 — Preservation | Storage collision via delegatecall |
| Day 53 | Level 17 — Recovery | Contract address prediction |
| Day 54 | Level 18 — MagicNumber | Raw bytecode deployment |
| Day 55 | Level 19 — Alien Codex | Array length underflow + storage slot 0 |
| Day 56 | Level 20 — Denial | Gas exhaustion DoS |
| Day 57 | Level 21 — Shop | View function manipulation |
| Day 58 | Level 22 — Dex | Price manipulation via swap |
| Day 59 | Level 23 — Dex Two | ERC20 approval exploit |
| Day 60 | Level 24 — Puzzle Wallet | Storage collision in proxy |

**End of Month 2 checkpoint:** You have solved Ethernaut levels 0–24. You know 15+ vulnerability classes by name and exploit. You write every exploit in Foundry.

---

## WEEKS 9–11 — Damn Vulnerable DeFi (Days 61–85)

**Go to: https://damnvulnerabledefi.xyz**

> These are harder than Ethernaut. Expect each to take 4–8 hours. That is normal.

| Days | Challenge | Core Vulnerability |
|---|---|---|
| Day 61–62 | Unstoppable | ERC20 balance vs internal accounting mismatch |
| Day 63–64 | Naive Receiver | Msg.sender not validated in flash loan |
| Day 65–66 | Truster | Arbitrary call in flash loan callback |
| Day 67–68 | Side Entrance | Flash loan deposit re-entrancy |
| Day 69–70 | The Rewarder | Flash loan + reward snapshot manipulation |
| Day 71–72 | Selfie | Governance token flash loan attack |
| Day 73–75 | Compromised | ECDSA private key from hex data |
| Day 76–77 | Puppet | AMM price oracle manipulation |
| Day 78–79 | Puppet V2 | Uniswap V2 TWAP oracle manipulation |
| Day 80–81 | Free Rider | NFT marketplace flash loan exploit |
| Day 82–83 | Backdoor | Gnosis Safe setup callback exploit |
| Day 84–85 | Climber | Timelock governance exploit |

**After every challenge:**
- Read the official writeup: check the DVDv4 README
- Read community writeups on GitHub: search "Damn Vulnerable DeFi [challenge name] writeup"
- Add to bug journal: what was the root cause? What would have prevented it?

---

## WEEKS 12–13 — Real Hack Post-Mortems (Days 86–98)

**Every day: read 2 real hack analyses**

**Go to: https://rekt.news — read each of these in order:**

| Day | Hack to study | Lesson |
|---|---|---|
| Day 86 | Poly Network ($611M) | Cross-chain message verification |
| Day 87 | Ronin Bridge ($625M) | Validator key compromise |
| Day 88 | Beanstalk ($182M) | Flash loan governance attack |
| Day 89 | Mango Markets ($114M) | Oracle price manipulation |
| Day 90 | Euler Finance ($197M) | Donation attack + health factor |
| Day 91 | Nomad Bridge ($190M) | Merkle root initialization bug |
| Day 92 | Wormhole ($325M) | Signature verification bypass |
| Day 93 | Cream Finance ($130M) | Flash loan + reentrancy |
| Day 94 | BadgerDAO ($120M) | Frontend + approval phishing |
| Day 95 | Harvest Finance ($34M) | Price oracle manipulation |
| Day 96 | Alpha Homora ($37M) | Flash loan + reentrancy |
| Day 97 | Wintermute ($160M) | Profanity vanity address |
| Day 98 | Review day — rewrite all 12 hacks in your own words |

**For each hack:** Read rekt.news article → Find the GitHub POC → Read the code → Understand the exact sequence of transactions.

**Best POC repo:** https://github.com/SunWeb3Sec/DeFiHackLabs

---

## WEEK 14 — Capture The Ether (Days 99–105)

**Go to: https://capturetheether.com**

| Day | Challenges to solve |
|---|---|
| Day 99 | Warmup section (all 3 challenges) |
| Day 100 | Lotteries: GuessTheNumber, GuessTheSecretNumber |
| Day 101 | Lotteries: GuessTheRandomNumber, GuessTheNewNumber |
| Day 102 | Math: TokenSale, TokenWhale |
| Day 103 | Math: RetirementFund, MappingMedley |
| Day 104 | Accounts: FuzzyIdentityChallenge |
| Day 105 | Review all solutions + update bug journal |

---

---

# PHASE 3 — Advanced Tooling
## Months 6–7 (Days 106–180)
### Goal: Automate 30% of your audit work. Find bugs machines find. Write invariants professionally.

---

## WEEK 15 — Slither Static Analysis (Days 106–112)

### Day 106 — Install & Run Slither

**Install:**
```bash
pip install slither-analyzer
# or
pip3 install slither-analyzer
```

**Study:**
1. Read: https://github.com/crytic/slither — entire README  
2. Read: https://github.com/crytic/slither/wiki/Detector-Documentation — bookmark this. It's your reference.

**Practice:**
```bash
# Run Slither on one of your old contracts
slither src/FundMe.sol --print human-summary
slither src/FundMe.sol --detect reentrancy-eth,reentrancy-no-eth
slither src/FundMe.sol --detect all 2>&1 | tee slither-report.txt
```

Read every warning. Understand why it's flagged.

---

### Days 107–112 — Slither on Real Protocols

Each day, pick one of these open-source DeFi protocols, clone it, and run Slither:

| Day | Protocol | Repo |
|---|---|---|
| Day 107 | Compound V2 | github.com/compound-finance/compound-protocol |
| Day 108 | Uniswap V2 Core | github.com/Uniswap/v2-core |
| Day 109 | Aave V2 | github.com/aave/protocol-v2 |
| Day 110 | OpenZeppelin Contracts | github.com/OpenZeppelin/openzeppelin-contracts |
| Day 111 | Curve Finance | github.com/curvefi/curve-contract |
| Day 112 | Write your first custom Slither detector — read: github.com/crytic/slither/wiki/How-to-write-a-detector |

**For each:** `slither . --detect all > report.txt` then read every single finding and classify it: real bug, false positive, or informational?

---

## WEEK 16 — Echidna Fuzzing (Days 113–119)

### Day 113 — Install & Learn Echidna

**Install:**
```bash
# Option 1: Docker (easiest)
docker pull ghcr.io/crytic/echidna/echidna

# Option 2: from releases
# https://github.com/crytic/echidna/releases
```

**Study:**
1. Read: https://github.com/crytic/building-secure-contracts/tree/master/program-analysis/echidna  
   → Complete tutorials 1, 2, 3 today

**Practice:**
```solidity
// echidna_test.sol
pragma solidity ^0.8.18;

contract Token {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    constructor() {
        balances[msg.sender] = 10000;
        totalSupply = 10000;
    }
    
    function transfer(address _to, uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
    }
    
    // Echidna property: total supply never changes
    function echidna_totalSupplyInvariant() public view returns (bool) {
        return totalSupply == 10000;
    }
    
    // Echidna property: no address has more than totalSupply
    function echidna_noOverflow() public view returns (bool) {
        return balances[msg.sender] <= totalSupply;
    }
}
```

```bash
echidna echidna_test.sol --contract Token
```

---

### Days 114–119 — Echidna on DeFi Protocols

Read and complete: https://github.com/crytic/building-secure-contracts/tree/master/program-analysis/echidna

Complete all tutorials in order:
- Tutorial 1: Basic properties
- Tutorial 2: Collecting and modifying corpus
- Tutorial 3: Filtering functions
- Tutorial 4: Reproducing a finding
- Tutorial 5: Checking ERC20 properties

---

## WEEK 17 — Foundry Invariant Testing Advanced (Days 120–126)

**Study:**
1. https://book.getfoundry.sh/forge/invariant-testing — reread with full attention  
2. Watch: https://www.youtube.com/watch?v=juyY-CTolac — Patrick Collins invariant testing deep dive

**Days 120–126:** For each day, write invariant tests for one real protocol:

| Day | Protocol | Key Invariant to Write |
|---|---|---|
| Day 120 | Your Bank contract (Day 20) | totalDeposited == address(this).balance |
| Day 121 | Your ERC20 (Day 8) | sum(all balances) == totalSupply |
| Day 122 | Your FundMe (Day 3) | only owner can drain contract |
| Day 123 | Your DEX (Day 14) | constant product k = x * y never decreases |
| Day 124 | Your NFT (Day 9) | ownerOf[tokenId] is always a valid non-zero address |
| Day 125 | WETH (write a mock) | totalSupply == sum of all deposits minus withdrawals |
| Day 126 | Review all invariants — what made some harder to write? |

---

## WEEK 18 — Complete Cyfrin Updraft Advanced (Days 127–133)

**Go to: https://updraft.cyfrin.io**  
**Enroll: "Advanced Foundry" + "Smart Contract Security" (remaining modules)**

| Day | Module |
|---|---|
| Day 127 | Advanced Foundry: Fuzz + Invariant deep dive |
| Day 128 | Advanced Foundry: Formal verification intro |
| Day 129 | Security: Audit report writing (how to write a professional finding) |
| Day 130 | Security: First audit walkthrough with Patrick |
| Day 131 | Security: Boss Bridge audit |
| Day 132 | Security: TSwap audit |
| Day 133 | Security: Thunderloan audit |

Each audit in Cyfrin is a full real audit exercise. Code along. Write your own report before seeing the official one.

---

## WEEK 19 — SWC Registry + Checklist Building (Days 134–140)

**Go to: https://swcregistry.io**

Each day, study 5 SWC entries in depth:

| Day | SWC IDs to study |
|---|---|
| Day 134 | SWC-100, 101, 102, 103, 104 |
| Day 135 | SWC-105, 106, 107, 108, 109 |
| Day 136 | SWC-110, 111, 112, 113, 114 |
| Day 137 | SWC-115, 116, 117, 118, 119 |
| Day 138 | SWC-120, 121, 122, 123, 124 |
| Day 139 | SWC-125, 126, 127, 128, 129 |
| Day 140 | Build your personal audit checklist — one row per SWC + any bugs you've seen in wargames |

**Your audit checklist template:**
```
## My Audit Checklist

### Access Control
- [ ] Are all sensitive functions protected by proper modifiers?
- [ ] Is tx.origin used anywhere? (SWC-115)
- [ ] Can anyone call initialize() on proxy contracts?

### Re-entrancy  
- [ ] Does any external call happen before state update? (SWC-107)
- [ ] Is the check-effects-interactions pattern followed?
- [ ] Are there ERC777/ERC1155 callbacks that could re-enter?

... (build this out for every category)
```

---

---

# PHASE 4 — Shadow Auditing & Contests
## Month 8 (Days 181–240)
### Goal: Submit first real findings. Build public portfolio. Get your first payout.

---

## WEEK 20 — Shadow Audit #1 (Days 141–147)

**What is a shadow audit?**  
Pick a Code4rena contest that has ALREADY ENDED and has a published report. Audit it yourself as if it were live. Then compare your findings with the official report.

**Your first shadow audit:**

1. Go to: https://code4rena.com/reports  
2. Pick any report from the last 6 months with a codebase under 500 lines  
3. Download the code from the linked GitHub repo  
4. Audit it yourself for 4 days:

**Day 141–144: The audit**
- Day 141: Read all code. Write notes. Map the architecture.
- Day 142: Run Slither. Triage the output.
- Day 143: Write Foundry tests for suspicious areas. Try to fuzz.
- Day 144: Write your findings report using this template:

```markdown
## Finding: [Title]

**Severity:** High / Medium / Low / Informational

**Description:**
What is the vulnerability?

**Impact:**
What can an attacker do? What is lost?

**Proof of Concept:**
```solidity
// Your exploit code here
```

**Recommended Fix:**
How to fix it?
```

**Day 145–147: The debrief**
- Read the official C4 report
- Compare your findings vs official findings
- For every High/Critical you missed: study why. Add to bug journal.
- Score yourself: Highs caught / Total Highs. Track this number every shadow audit.

---

## WEEKS 21–22 — Shadow Audits #2–#5 (Days 148–161)

Repeat the exact shadow audit process for 4 more completed contests.

**Where to find good ones:**
- https://code4rena.com/reports — filter by size (pick under 1000 lines first)
- https://github.com/solodit/solodit — search past contests

**Track your progress:**

| Shadow Audit # | Protocol | Lines of Code | Highs Found | Highs Missed | Score |
|---|---|---|---|---|---|
| 1 | — | — | — | — | —% |
| 2 | — | — | — | — | —% |
| 3 | — | — | — | — | —% |
| 4 | — | — | — | — | —% |
| 5 | — | — | — | — | —% |

**Gate: When you are catching >50% of Highs consistently → enter a live contest.**

---

## WEEK 23 — Enter Your First Live Contest (Days 162–168)

**Go to: https://codehawks.cyfrin.io**  
→ Look for "First Flights" — these are beginner-tier competitions with smaller codebases

**Alternatively: https://code4rena.com**  
→ Look for active contests with smaller scope

**How to compete:**
1. Read ALL the code on Day 1
2. Focus only on HIGH severity findings — Medium/Low findings are noise when starting
3. Use your audit checklist (from Day 140) systematically
4. Submit every potential finding even if uncertain of severity
5. Write clean, professional reports using your template

**Your daily contest routine:**
- Morning: Read codebase + architecture
- Afternoon: Run Slither + Echidna + write Foundry tests
- Evening: Write findings reports

**Expected result for first contest:** $0–$200. That is completely normal. The goal is the experience, not the payout.

---

## WEEK 24 — Solodit Daily Reading (Days 169–175)

**Starting now and forever: daily reading**

**Every morning (30 minutes):**
1. Go to: https://solodit.xyz  
2. Search for one vulnerability class you studied  
3. Read 3–5 real contest findings from different protocols  
4. Understand: was it a code bug, a design bug, or a logic bug?  
5. Add interesting ones to your bug journal

**This daily habit is worth more than any single course. Do it forever.**

---

## WEEK 25–26 — Portfolio Building (Days 176–190)

**Day 176–180: Set up your public presence**

1. Create a GitHub repo called `security-portfolio`:
```
security-portfolio/
├── README.md          (your audit profile)
├── shadow-audits/     (all your shadow audit reports)
│   ├── audit-01-protocol-name/
│   │   ├── report.md
│   │   └── poc/
├── wargames/
│   ├── ethernaut/
│   └── damn-vulnerable-defi/
├── tools/
│   └── audit-checklist.md
```

2. Your README.md should contain:
   - Your background (C, RE, security)
   - Vulnerability classes you specialize in
   - Protocols you've shadow-audited
   - Contest submissions (even $0 ones)
   - Your audit checklist

**Day 181–190: Enter 2 more live contests**

- Code4rena: https://code4rena.com/contests  
- Sherlock: https://audits.sherlock.xyz/contests (harder, better payouts)

---

## ONGOING — After Month 8

Once you complete this roadmap, you are not done. Auditing is a skill that compounds. Here's what you do from Day 191 onwards:

### Weekly routine (permanent)
- **Monday–Friday:** 2 live contest audits or 1 shadow audit per week
- **Daily:** Solodit reading (30 min) + Twitter feed from your follow list
- **Weekly:** Read 2 post-mortems from DeFiHackLabs
- **Monthly:** Write a public technical blog post on Mirror.xyz or your GitHub about a bug you found or studied

### Resources to consume as you grow

| Resource | When to use |
|---|---|
| https://solodit.xyz | Daily — forever |
| https://rekt.news | Weekly — forever |
| https://github.com/SunWeb3Sec/DeFiHackLabs | Weekly — study 2 POCs/week |
| https://www.rareskills.io/blog | When studying a new topic (AMMs, oracles, ZK) |
| https://github.com/Cyfrin/security-and-auditing-full-course-s23 | Supplementary reference |
| https://immunefi.com/learn/ | Bug bounty methodology |

### When to apply to firms
- You have 5+ shadow audit reports publicly on GitHub
- You have 3+ live contest submissions
- You have at least 1 payout (even $50)
- You can confidently discuss re-entrancy, storage collisions, and oracle manipulation in depth

**Target firms (all have open applications):**
- Cyfrin: cyfrin.io/careers
- Guardian Audits: guardianaudits.com
- Pashov Audit Group: pashov.net
- MixBytes: mixbytes.io

---

---

# MASTER VULNERABILITY CHEATSHEET

Memorize these. They appear in >80% of all High/Critical findings.

| # | Vulnerability | Quick Pattern | Tool to detect |
|---|---|---|---|
| 1 | Re-entrancy | external call before state update | Slither: reentrancy-eth |
| 2 | Integer overflow | unchecked math pre-0.8 | Slither: integer-overflow |
| 3 | tx.origin auth | `require(tx.origin == owner)` | Slither: tx-origin |
| 4 | Storage collision | proxy + delegatecall + wrong layout | Manual |
| 5 | Flash loan attack | borrow → manipulate → repay in 1 tx | Manual |
| 6 | Oracle manipulation | spot price used for accounting | Manual |
| 7 | Missing access control | public/external function with no check | Slither: suicidal |
| 8 | Signature replay | signature reused across chains or time | Manual |
| 9 | Uninitialized proxy | `initialize()` not called or callable by anyone | Slither: uninitialized-local |
| 10 | Precision loss | division before multiplication | Manual |
| 11 | Weak randomness | blockhash/timestamp as random | Slither: weak-prng |
| 12 | DoS via ETH push | `transfer()` to untrusted address | Manual |
| 13 | Read-only re-entrancy | view function reads stale state during re-entry | Manual |
| 14 | ERC20 fee-on-transfer | assuming received == sent | Manual |
| 15 | Front-running | slippage, approve/transferFrom race | Manual |

---

# QUICK REFERENCE

| Resource | URL | When to use |
|---|---|---|
| Remix IDE | remix.ethereum.org | All of Month 1–2 |
| evm.codes | evm.codes | Opcode reference |
| Cyfrin Updraft | updraft.cyfrin.io | Main course platform |
| Secureum | secureum.substack.com | Security theory |
| Ethernaut | ethernaut.openzeppelin.com | Wargame 1 |
| Damn Vulnerable DeFi | damnvulnerabledefi.xyz | Wargame 2 |
| Capture The Ether | capturetheether.com | Wargame 3 |
| DeFiHackLabs | github.com/SunWeb3Sec/DeFiHackLabs | Real hack POCs |
| Rekt News | rekt.news | Post-mortems |
| Solodit | solodit.xyz | Contest findings aggregator |
| Code4rena | code4rena.com | First contest platform |
| Codehawks | codehawks.cyfrin.io | Beginner contests |
| SWC Registry | swcregistry.io | Vuln reference |
| Foundry Book | book.getfoundry.sh | Tooling docs |
| Slither | github.com/crytic/slither | Static analysis |
| Building Secure Contracts | github.com/crytic/building-secure-contracts | Echidna tutorials |
| OZ Contracts | github.com/OpenZeppelin/openzeppelin-contracts | Standard implementations |
| Solidity Docs | docs.soliditylang.org | Language reference |

---

*Follow this. Don't deviate. Don't add more resources. The problem is never lack of resources — it's consistency. See you at Month 8.*
