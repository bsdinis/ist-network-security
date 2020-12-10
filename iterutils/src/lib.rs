use std::convert::TryInto;

pub trait MapIntoExt<T> {
    fn map_into(self) -> T;
}

impl<U, T> MapIntoExt<Option<T>> for Option<U>
where
    U: Into<T>,
{
    fn map_into(self) -> Option<T> {
        self.map(|u| u.into())
    }
}
impl<U, T> MapIntoExt<Vec<T>> for Vec<U>
where
    U: Into<T>,
{
    fn map_into(mut self) -> Vec<T> {
        self.drain(..).map(|u| u.into()).collect()
    }
}

pub trait MapTryIntoExt<T, E> {
    fn map_try_into(self) -> Result<T, E>;
}

impl<U, T, E> MapTryIntoExt<Option<T>, E> for Option<U>
where
    U: TryInto<T, Error = E>,
{
    fn map_try_into(self) -> Result<Option<T>, E> {
        self.map(|u| u.try_into()).transpose()
    }
}

pub trait TryCollectExt<V, E, B> {
    fn try_collect(self) -> Result<B, E>;
}

impl<I, V, E> TryCollectExt<V, E, Vec<V>> for I
where
    I: Iterator<Item = Result<V, E>>,
{
    fn try_collect(mut self) -> Result<Vec<V>, E> {
        let mut res = Vec::with_capacity(self.size_hint().0);

        while let Some(item) = self.next() {
            res.push(item?);
        }

        Ok(res)
    }
}
