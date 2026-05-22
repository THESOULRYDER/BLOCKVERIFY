// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileIntegrity {
    
    struct FileRecord {
        string fileName;
        string merkleRoot;
        string fileHash;
        uint256 timestamp;
        address uploader;
        bool exists;
    }

    mapping(uint256 => FileRecord) private files;
    mapping(string => uint256[]) private fileNameToIds;
    uint256 public fileCount;
    address public owner;

    event FileStored(uint256 indexed fileId, string fileName, string merkleRoot, uint256 timestamp);
    event FileVerified(uint256 indexed fileId, bool isIntact, uint256 timestamp);
    event TamperDetected(uint256 indexed fileId, string fileName, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    constructor() {
        owner = msg.sender;
        fileCount = 0;
    }

    function storeFile(
        string memory _fileName,
        string memory _merkleRoot,
        string memory _fileHash
    ) public returns (uint256) {
        fileCount++;
        files[fileCount] = FileRecord({
            fileName: _fileName,
            merkleRoot: _merkleRoot,
            fileHash: _fileHash,
            timestamp: block.timestamp,
            uploader: msg.sender,
            exists: true
        });
        fileNameToIds[_fileName].push(fileCount);
        emit FileStored(fileCount, _fileName, _merkleRoot, block.timestamp);
        return fileCount;
    }

    function getFile(uint256 _fileId) public view returns (
        string memory fileName,
        string memory merkleRoot,
        string memory fileHash,
        uint256 timestamp,
        address uploader
    ) {
        require(files[_fileId].exists, "File record does not exist");
        FileRecord memory f = files[_fileId];
        return (f.fileName, f.merkleRoot, f.fileHash, f.timestamp, f.uploader);
    }

    function verifyFile(uint256 _fileId, string memory _newHash) public returns (bool) {
        require(files[_fileId].exists, "File record does not exist");
        bool intact = keccak256(bytes(files[_fileId].fileHash)) == keccak256(bytes(_newHash));
        emit FileVerified(_fileId, intact, block.timestamp);
        if (!intact) {
            emit TamperDetected(_fileId, files[_fileId].fileName, block.timestamp);
        }
        return intact;
    }

    function getFileIdsByName(string memory _fileName) public view returns (uint256[] memory) {
        return fileNameToIds[_fileName];
    }

    function getTotalFiles() public view returns (uint256) {
        return fileCount;
    }
}
