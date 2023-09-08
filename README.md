INPROGRESS:
/mold.h
    HyperLogLog
        Перенесен в hyperloglog.rs
        merge - update_maximum удален
    TarWriter 
        Перенесен из mold.h в tar.rs
        Деструктор убран, так как File закрывается автоматически
        TODO: append - не понятно как сделать compile time assert 
        Заменен тип path на Path
        open - тип возврата std::unique_ptr<TarWriter> заменен на TarWriter так как
        file не нужен больше деструктор

FINISHED:
/hyperloglog.cc
/tar.cc
    UstarHeader
        Добавилось repr(C) и Default
        Добавился метод as_slice
        TODO: finalize - пока не ясно для чего assert и как с ним быть 
/uuid.cc
